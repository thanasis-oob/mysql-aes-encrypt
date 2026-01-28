<?php

namespace Thanous\AESEncrypt;

use Illuminate\Database\Events\ConnectionEstablished;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;

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
            $connectionManager = new AesConnectionManager($connection);
            $connectionManager->setupConnection();
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
