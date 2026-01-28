<?php

namespace Thanous\AESEncrypt\Tests\Unit;

use Illuminate\Database\Connection;
use PHPUnit\Framework\Attributes\Test;
use Thanous\AESEncrypt\AesConnectionManager;
use Thanous\AESEncrypt\Database\Query\Grammars\MySqlGrammarEncrypt;
use Thanous\AESEncrypt\Tests\TestCase;

final class AesConnectionManagerTest extends TestCase
{
    /**
     * Create a Connection mock (not ConnectionInterface) so we can mock getDriverName().
     * Also captures statement calls into $statements for assertions.
     */
    private function makeConnectionMock(string $driver, ?string $effectiveBem, array &$statements): Connection
    {
        $conn = $this->getMockBuilder(Connection::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getDriverName', 'statement', 'selectOne', 'setQueryGrammar'])
            ->getMock();

        $conn->method('getDriverName')->willReturn($driver);

        $conn->method('selectOne')->willReturnCallback(function (string $sql) use ($effectiveBem) {
            if ($sql === 'SELECT @@SESSION.block_encryption_mode AS bem') {
                return (object) ['bem' => $effectiveBem];
            }
            return (object) [];
        });

        $conn->method('statement')->willReturnCallback(function (string $sql, array $bindings = []) use (&$statements) {
            $statements[] = [$sql, $bindings];
            return true;
        });

        return $conn;
    }

    #[Test]
    public function it_skips_when_driver_is_not_supported(): void
    {
        $this->app['config']->set('aesEncrypt.key', 'passphrase');
        $this->app['config']->set('aesEncrypt.mode', 'aes-256-cbc');
        $this->app['config']->set('aesEncrypt.use_iv', false);
        $this->app['config']->set('aesEncrypt.normalize_key_length', true);

        $statements = [];
        $conn = $this->makeConnectionMock('sqlite', 'aes-256-cbc', $statements);

        $conn->expects($this->never())->method('setQueryGrammar');

        (new AesConnectionManager($conn))->setupConnection();

        $this->assertCount(0, $statements);
    }

    #[Test]
    public function it_sets_mode_key_and_swaps_grammar_for_mysql(): void
    {
        $this->app['config']->set('aesEncrypt.key', 'passphrase');
        $this->app['config']->set('aesEncrypt.mode', 'aes-256-cbc');
        $this->app['config']->set('aesEncrypt.use_iv', false);
        $this->app['config']->set('aesEncrypt.normalize_key_length', true);

        $statements = [];
        $conn = $this->makeConnectionMock('mysql', 'aes-256-cbc', $statements);

        $conn->expects($this->once())
            ->method('setQueryGrammar')
            ->with($this->isInstanceOf(MySqlGrammarEncrypt::class));

        (new AesConnectionManager($conn))->setupConnection();

        // mode + key
        $this->assertCount(2, $statements);

        [$sql1, $bind1] = $statements[0];
        $this->assertSame('SET @@SESSION.block_encryption_mode = ?', $sql1);
        $this->assertSame(['aes-256-cbc'], $bind1);

        [$sql2, $bind2] = $statements[1];
        $this->assertSame('SET @AESKEY = UNHEX(?)', $sql2);
        $this->assertCount(1, $bind2);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $bind2[0]); // 32 bytes => 64 hex
    }

    #[Test]
    public function it_does_not_set_mode_when_mode_is_empty(): void
    {
        $this->app['config']->set('aesEncrypt.key', 'passphrase');
        $this->app['config']->set('aesEncrypt.mode', null);
        $this->app['config']->set('aesEncrypt.use_iv', false);
        $this->app['config']->set('aesEncrypt.normalize_key_length', true);

        $statements = [];
        $conn = $this->makeConnectionMock('mysql', 'aes-256-cbc', $statements);

        $conn->expects($this->once())
            ->method('setQueryGrammar')
            ->with($this->isInstanceOf(MySqlGrammarEncrypt::class));

        (new AesConnectionManager($conn))->setupConnection();

        // Only key
        $this->assertCount(1, $statements);

        [$sql, $bind] = $statements[0];
        $this->assertSame('SET @AESKEY = UNHEX(?)', $sql);
        $this->assertCount(1, $bind);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $bind[0]);
    }

    #[Test]
    public function it_does_not_set_key_when_key_is_empty(): void
    {
        $this->app['config']->set('aesEncrypt.key', '');
        $this->app['config']->set('aesEncrypt.mode', 'aes-256-cbc');
        $this->app['config']->set('aesEncrypt.use_iv', false);
        $this->app['config']->set('aesEncrypt.normalize_key_length', true);

        $statements = [];
        $conn = $this->makeConnectionMock('mysql', 'aes-256-cbc', $statements);

        $conn->expects($this->once())
            ->method('setQueryGrammar')
            ->with($this->isInstanceOf(MySqlGrammarEncrypt::class));

        (new AesConnectionManager($conn))->setupConnection();

        // Only mode (no key at all)
        $this->assertCount(1, $statements);

        [$sql, $bind] = $statements[0];
        $this->assertSame('SET @@SESSION.block_encryption_mode = ?', $sql);
        $this->assertSame(['aes-256-cbc'], $bind);
    }

    #[Test]
    public function it_generates_correct_key_hex_length_based_on_effective_mode(): void
    {
        $statements = [];

        $conn128 = $this->makeConnectionMock('mysql', 'aes-128-cbc', $statements);
        $m128 = new AesConnectionManager($conn128);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $m128->generateNormalizeAesKeyHex('passphrase'));

        $conn192 = $this->makeConnectionMock('mysql', 'aes-192-cbc', $statements);
        $m192 = new AesConnectionManager($conn192);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{48}$/', $m192->generateNormalizeAesKeyHex('passphrase'));

        $conn256 = $this->makeConnectionMock('mysql', 'aes-256-cbc', $statements);
        $m256 = new AesConnectionManager($conn256);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $m256->generateNormalizeAesKeyHex('passphrase'));
    }
}
