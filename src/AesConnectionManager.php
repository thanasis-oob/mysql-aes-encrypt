<?php

namespace Thanous\AESEncrypt;

use Exception;
use Illuminate\Database\ConnectionInterface;
use Thanous\AESEncrypt\Database\Query\Grammars\MySqlGrammarEncrypt;

final class AesConnectionManager
{

    protected ConnectionInterface $connection;

    public function __construct(ConnectionInterface $connection)
    {
        $this->connection = $connection;
    }

    public function setupConnection(): void
    {
        if (!$this->isSupportedDriver()) {
            return;
        }

        $this->initAesConfig();
        $this->defineEncryptionVariables();

        // Swap grammar (no behavior change yet, just proving hook works)
        $this->connection->setQueryGrammar(new MySqlGrammarEncrypt());
    }

    public function isSupportedDriver(): bool
    {
        return in_array($this->connection->getDriverName(), AesConfig::supportedDrivers(), true);
    }

    public function initAesConfig()
    {
        AesConfig::set(
            key: config('aesEncrypt.key'),
            aesMode: config('aesEncrypt.mode'),
            useIv: config('aesEncrypt.use_iv'),
            normalizeKeyLength: config('aesEncrypt.normalize_key_length')
        );
    }

    /**
     * Derive the correct-length AES key for the *effective* MySQL session block_encryption_mode.
     *
     * - Reads @@SESSION.block_encryption_mode (so default vs configured is handled automatically).
     * - Derives key as SHA-256(passphrase) truncated to 16/24/32 bytes depending on 128/192/256.
     * - Optionally stores it into @AESKEY as BINARY using UNHEX(?) to avoid charset surprises.
     *
     * @return void
     */
    private function defineEncryptionVariables(): void
    {
        $this->defineAesMode();
        $this->defineAesKey();
    }

    private function defineAesMode(): void
    {
        if (!empty(AesConfig::aesMode())) {
            $this->connection->statement('SET @@SESSION.block_encryption_mode = ?', [AesConfig::aesMode()]);
        }
    }

    private function defineAesKey(): void
    {
        $plainKey = AesConfig::key();

        if (empty($plainKey)) {
            return;
        }

        if (AesConfig::shouldNormalizeKeyLength() && $this->extractUsedAesMode() !== null) {
            $keyHex = $this->generateNormalizeAesKeyHex($plainKey);

            // 4) set @AESKEY as a binary value in the session
            // Store as binary to avoid encoding/collation issues
            $this->connection->statement('SET @AESKEY = UNHEX(?)', [$keyHex]);
        } else {
            $this->connection->statement('SET @AESKEY = ?', [$plainKey]);
        }
    }

    public function generateNormalizeAesKeyHex(string $plainKey): string
    {
        // 1) Read the *effective* session mode (already includes server default if you didn't set it)
        $usedAesMode = $this->extractUsedAesMode($this->connection);
        // 2) Parse key size from mode string like: "aes-256-cbc"
        $keyByteLength = $this->detectAesModeAppropriateKeyByteLength($usedAesMode, $plainKey);

        // 3) Derive bytes: SHA-256(passphrase) -> truncate to 16/24/32 bytes
        $hash32 = hash('sha256', $plainKey, true); // 32 raw bytes
        $keyBin = substr($hash32, 0, $keyByteLength);

        return bin2hex($keyBin);
    }

    public function extractUsedAesMode(): ?string
    {
        try{
            $row = $this->connection->selectOne('SELECT @@SESSION.block_encryption_mode AS bem');
            return $row->bem ?? null;
        } catch (Exception $e) {
            return null;
        }
    }

    private function detectAesModeAppropriateKeyByteLength(?string $usedAesMode, string $plainKey): int
    {
        // 2) Parse key size from mode string like: "aes-256-cbc"
        // If parsing fails, fall back to 128 (safe default assumption for key-sizing)
        $bits = 128;
        if (is_string($usedAesMode) && preg_match('/^aes-(128|192|256)-/i', $usedAesMode, $m)) {
            $bits = (int) $m[1];
        }

        return intdiv($bits, 8);
    }

}
