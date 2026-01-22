<?php

namespace mrzainulabideen\AESEncrypt;

use Illuminate\Database\Events\ConnectionEstablished;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use mrzainulabideen\AESEncrypt\Database\Query\Grammars\MySqlGrammarEncrypt;

class AesEncryptServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        // Allow publishing the package config into the host app
        $this->publishes([
            __DIR__ . '/config/aesEncrypt.php' => config_path('aesEncrypt.php'),
        ], 'config');

        /**
         * MVP: When a DB connection is established:
         * - Only for mysql connections
         * - set session variables (mode + key)
         * - replace the query grammar with our subclass
         */
        Event::listen(ConnectionEstablished::class, function (ConnectionEstablished $event) {
            $connection = $event->connection;

            if ($connection->getDriverName() !== 'mysql') {
                return;
            }

            $aesMode = config('aesEncrypt.mode');
            $key  = config('aesEncrypt.key');
            $useIv = config('aesEncrypt.use_iv');
            AesConfig::set($key, $aesMode, $useIv);

            if (!empty($aesMode)) {
                $connection->statement('SET @@SESSION.block_encryption_mode = ?', [$aesMode]);
            }

            if (!empty($key)) {
                // store key in a session variable for use in SQL expressions later
                $connection->statement('SET @AESKEY = ?', [$key]);
            }

            // Swap grammar (no behavior change yet, just proving hook works)
            $connection->setQueryGrammar(new MySqlGrammarEncrypt());
        });
    }

    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/config/aesEncrypt.php',
            'aesEncrypt'
        );
    }
}
