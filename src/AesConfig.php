<?php

namespace mrzainulabideen\AESEncrypt;

final class AesConfig
{
    private static string $key = '';
    private static ?string $aesMode = null;
    private static bool $useIv = false;

    public static function set(string $key, ?string $aesMode, bool $useIv): void
    {
        self::$key = $key;
        self::$aesMode = $aesMode;
        self::$useIv = $useIv;
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
}
