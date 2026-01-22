# Laravel 11 MySQL AES Encrypt / Decrypt (Grammar-based)

> **Version:** v11.0.0  
> **License:** Apache 2.0  
> **Laravel:** 11.x  
> **Database:** MySQL / MariaDB (see limitations)

This package provides **transparent column-level encryption and decryption at the MySQL layer** using native `AES_ENCRYPT` / `AES_DECRYPT`, implemented by **extending Laravel’s MySQL query grammar**.

It is a fork of  
https://github.com/devmaster10/mysql-aes-encrypt  
with a **modernized implementation**, updated for Laravel 11.

---

## ⚠️ Important Notes (Read First)

- Encrypted columns **MUST be stored as BLOB / VARBINARY**
- Encryption / decryption happens **at SQL compilation time**
- The package **does NOT use Eloquent accessors or mutators**
- The following are **NOT supported**:
    - `groupLimit()` queries
    - JSON columns / JSON selectors
    - Automatic handling of raw SQL expressions (`DB::raw`)
- Long-running processes (queue workers, Octane, Swoole, RoadRunner) **require special attention** (see below)

---

## Features

- Transparent encryption & decryption using native MySQL functions
- Optional IV-based encryption (MySQL ≥ 8 / compatible MariaDB)
- Supports comparison operators on encrypted columns:
    - `=`, `!=`, `<`, `>`, `between`, `like`, `in`
- No changes to Eloquent query syntax
- Uses MySQL **SESSION variables** to protect the encryption key

---

## Installation

```bash
composer require mrzainulabideen/aesencrypt:^11.0
```

Laravel 11 auto-discovers the service provider.

---

## Configuration

Publish the config file:

```bash
php artisan vendor:publish --provider="mrzainulabideen\AESEncrypt\AesEncryptServiceProvider"
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

```php
use Illuminate\Database\Eloquent\Model;
use mrzainulabideen\AESEncrypt\Database\Eloquent\Concerns\EncryptableModel;

class User extends Model
{
    use EncryptableModel;

    protected array $fillableEncrypt = [
        'email',
        'name',
    ];
}
```

---

## Creating Tables for Encrypted Columns

Encrypted columns **must be binary**.

```php
Schema::create('users', function (Blueprint $table) {
    $table->id();
    $table->binary('email');
    $table->binary('name');
    $table->timestamps();
});
```

---

## Encrypting Existing Plain Data (IMPORTANT)

### ⚠️ Plain → Encrypted migration cannot be done in-place

Use a **new table + SQL-based copy**.

```sql
SET @@SESSION.block_encryption_mode = 'aes-256-cbc';
SET @AESKEY = 'your-secret-key';

INSERT INTO enc_users (id, email, name, created_at, updated_at)
SELECT
  id,
  AES_ENCRYPT(email, @AESKEY),
  AES_ENCRYPT(name, @AESKEY),
  created_at,
  updated_at
FROM users;
```

---

## Raw Expressions

Raw expressions (`DB::raw`) are **NOT automatically encrypted**.
Manual handling is required.

---

## Unsupported Features

- `groupLimit()`
- JSON columns / selectors
- JSON functions

---

## Long-Running Processes Warning ⚠️

This package relies on MySQL **SESSION variables**.
In long-running workers, these may be lost, causing encryption/decryption failures.

Always ensure connections are re-initialized.

---