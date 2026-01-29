<?php

namespace Thanous\AESEncrypt\Database\Query\Grammars;

use Thanous\AESEncrypt\AesConfig;

class EncryptExpressions
{
    /**
     * Decide if we should use IV-based encryption/decryption.
     * Works as a feature toggle so you can run on MariaDB 10.6 (false)
     * and on MySQL that supports IV + mode (true).
     */
    public static function useIv(): bool
    {
        return AesConfig::useIv();
    }

    /**
     * Build an SQL expression that encrypts the given SQL value expression.
     * Example $sqlValue: "?" or "`users`.`first_name_plain`"
     */
    public static function encrypt(string $sqlValue): string
    {
        if (self::useIv()) {
            // Store: ciphertext + ".iv." + raw IV bytes
            return "CONCAT(
                AES_ENCRYPT({$sqlValue}, @AESKEY, @iv := RANDOM_BYTES(16)),
                '.iv.',
                @iv
            )";
        }

        // MariaDB-compatible: no IV argument
        return "AES_ENCRYPT({$sqlValue}, @AESKEY)";
    }

    /**
     * Build an SQL expression that decrypts the given SQL column expression.
     * Example $column: "`users`.`first_name`"
     */
    public static function decrypt(string $column): string
    {
        $aesParameters = [
            'columnValueName' => $column,
            'aesKey' => '@AESKEY',
        ];

        if (self::useIv()) {
            $aesParameters['columnValueName'] = "SUBSTRING_INDEX({$column}, '.iv.', 1)";
            $aesParameters['iv'] = "SUBSTRING_INDEX({$column}, '.iv.', -1)";
        }
        $aesParametersExpression = implode(', ', array_filter($aesParameters));
        $decryptedColumn = "AES_DECRYPT({$aesParametersExpression})";

        return "CONVERT({$decryptedColumn} USING utf8mb4)";
    }
}
