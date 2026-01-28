<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Encryption Key
    |--------------------------------------------------------------------------
    | The secret key used by MySQL AES_ENCRYPT/AES_DECRYPT.
    | Recommended: set via env MYSQL_AES_KEY in your Laravel app.
    */
    'key' => env('MYSQL_AES_KEY'),

    /*
    |--------------------------------------------------------------------------
    | Whether should normalize key length depends on the encryption algorithm
    |--------------------------------------------------------------------------
    | Recommended for production mode.
    | IMPORTANT: On switching, changes the aes key, so be careful.
    */
    'normalize_key_length' => env('MYSQL_AES_NORMALIZE_KEY_LENGTH', false),

    /*
    |--------------------------------------------------------------------------
    | Use AES IV (MySQL only)
    |--------------------------------------------------------------------------
    | If true:
    |   AES_ENCRYPT(str, key, iv) + ".iv."+iv will be used
    | If false:
    |   AES_ENCRYPT(str, key) only (MariaDB compatible)
    */
    'use_iv' => env('MYSQL_AES_USE_IV', false),

    /*
    |--------------------------------------------------------------------------
    | MySQL block encryption mode
    |--------------------------------------------------------------------------
    | Example values:
    | - aes-256-cbc
    | - aes-128-cbc
    | Depends on your MySQL server configuration/support.
    |
    | If null/empty, the package will NOT set block_encryption_mode.
    */
    'mode' => env('MYSQL_AES_MODE', null),
];