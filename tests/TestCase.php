<?php

namespace mrzainulabideen\AESEncrypt\Tests;

use Illuminate\Database\Connection;
use Illuminate\Database\Connectors\SQLiteConnector;
use Illuminate\Database\Query\Processors\MySqlProcessor;
use Illuminate\Database\SQLiteConnection;
use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\TestCase as Orchestra;
use mrzainulabideen\AESEncrypt\Database\Query\Grammars\MySqlGrammarEncrypt;
use mrzainulabideen\AESEncrypt\Database\Query\BuilderEncrypt;
use mrzainulabideen\AESEncrypt\AesConfig;

abstract class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();

        // Make sure config is deterministic for compilation tests
        AesConfig::set('test-key', 'aes-256-cbc', false);
    }

    /**
     * We don't need a real MySQL connection. We only need:
     * - a Connection instance
     * - a grammar instance
     * - a post processor
     *
     * SQLiteConnection works fine for compilation because the grammar we compile with is MySqlGrammarEncrypt.
     */
    protected function makeEncryptBuilder(array $encryptable = ['email']): BuilderEncrypt
    {
        $connection = $this->makeFakeConnection();

        $grammar = new MySqlGrammarEncrypt();
        $connection->setQueryGrammar($grammar);

        $builder = new BuilderEncrypt(
            $connection,
            $grammar,
            $connection->getPostProcessor()
        );

        return $builder->setEncryptable($encryptable);
    }

    protected function makePlainBuilder()
    {
        // Normal Laravel builder (not BuilderEncrypt)
        $connection = $this->makeFakeConnection();

        return $connection->table('users');
    }

    protected function makeFakeConnection(): Connection
    {
        $conn = new Connection(
        // PDO not needed if we never execute
            null,
            'database',
            '',
            []
        );

        $conn->setQueryGrammar(new MySqlGrammarEncrypt());
        $conn->setPostProcessor(new MySqlProcessor());

        return $conn;
    }

    protected function norm(string $sql): string
    {
        return preg_replace('/\s+/', ' ', trim($sql));
    }
}
