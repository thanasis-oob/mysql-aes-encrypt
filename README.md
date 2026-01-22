# Laravel 11 MySQL AES Encrypt / Decrypt (Grammar-based)

> **Version:** v11.0.0  
> **License:** Apache 2.0  
> **Laravel:** 11.x  
> **Database:** MySQL / MariaDB (see limitations)

This package provides **transparent column-level encryption and decryption at the MySQL layer** using native `AES_ENCRYPT` / `AES_DECRYPT`, implemented by **extending Laravel’s MySQL query grammar**.

## Fork lineage & attribution

This repository is a fork of:

- https://github.com/mrzainulabideen/mysql-aes-encrypt  
  which itself is a fork of
- https://github.com/redsd/mysql-aes-encrypt  
  which is originally based on
- https://github.com/devmaster10/mysql-aes-encrypt

This fork introduces many changes for Laravel 11 compatibility, and a rewritten grammar-based implementation.

In accordance with the **Apache License 2.0**, attribution to the original upstream project(s) is preserved in this documentation.

---

## ⚠️ Important Notes (Read First)

- Encrypted columns **MUST be stored as BLOB / VARBINARY**
- Encryption / decryption happens **at SQL compilation time**
- The package **does NOT use Eloquent accessors or mutators**
- The following are **NOT supported**:
  - `groupLimit()` queries
  - JSON columns / JSON selectors
  - Automatic handling of raw SQL expressions (`DB::raw`)
- Long-running processes (queue workers, Octane, Swoole, RoadRunner) **require special attention**

---

## Package information

- Transparent encryption & decryption using native MySQL functions
- Optional IV-based encryption (MySQL ≥ 8 / compatible MariaDB)
- No changes to Eloquent query syntax

---

## Installation

```bash
composer require thanous/mysql-aes-encrypt:^11.0
```

Laravel 11 auto-discovers the service provider.

---

## Configuration

```bash
php artisan vendor:publish --provider="Thanous\AESEncrypt\AesEncryptServiceProvider"
```

### Config options (`config/aesEncrypt.php`)

```php
return [
    'key' => env('APP_AESENCRYPT_KEY'),
    'mode' => env('APP_AESENCRYPT_MODE', null),
    'use_iv' => env('APP_AESENCRYPT_USE_IV', false),
];
```

### `.env`

```env
APP_AESENCRYPT_KEY=your-secret-key
APP_AESENCRYPT_MODE=aes-256-cbc
APP_AESENCRYPT_USE_IV=true
```

---

## Updating Your Eloquent Models

Models with encrypted columns must use the `EncryptableModel` trait.

(The interface `EncryptableModelContract` is not required for functional reasons)

```php
use Illuminate\Database\Eloquent\Model;
use Thanous\AESEncrypt\Database\Eloquent\Concerns\EncryptableModel;
use Thanous\AESEncrypt\Database\Eloquent\Contracts\EncryptableModelContract;

class User extends Model implements EncryptableModelContract
{
    use EncryptableModel;

    protected array $encryptable = [
        'email',
        'name',
    ];
}
```

---

## Encrypting Existing Data

Plain data **must be migrated** into encrypted binary columns.
In-place encryption is not supported.

---

## Limitations

- No JSON columns
- No groupLimit
- Raw expressions require manual handling
- SESSION variables may be lost in long-running DB connections
