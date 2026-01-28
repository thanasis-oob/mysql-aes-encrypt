<?php

namespace Thanous\AESEncrypt;

use Illuminate\Database\ConnectionInterface;

final class AesConfig
{
    private static string $key = '';
    private static bool $normalizeKeyLength = false;
    private static ?string $aesMode = null;
    private static bool $useIv = false;

    public static function set(string $key, ?string $aesMode, bool $useIv, bool $normalizeKeyLength): void
    {
        self::$key = $key;
        self::$aesMode = $aesMode;
        self::$useIv = $useIv;
        self::$normalizeKeyLength = $normalizeKeyLength;
    }

    public static function supportedDrivers():array
    {
        return [
            'mysql',
        ];
    }

    public static function key(): string
    {
        return self::$key;
    }

    public static function aesMode(): ?string
    {
        return self::$aesMode;
    }

    public static function useIv(): bool
    {
        return self::$useIv;
    }

    public static function shouldNormalizeKeyLength(): bool
    {
        return self::$normalizeKeyLength;
    }
}
