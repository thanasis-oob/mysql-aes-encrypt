<?php

namespace mrzainulabideen\AESEncrypt\Database\Query;

use Illuminate\Database\Query\Builder as BaseBuilder;

/**
 * Query Builder that stores which columns should be encrypted/decrypted.
 * The grammar will read this list from the Builder instance at compile time.
 */
class BuilderEncrypt extends BaseBuilder
{
    /**
     * @var array<string>
     */
    protected array $encryptable = [];

    /**
     * Set encrypted columns for this builder.
     *
     * @param array<string> $columns
     */
    public function setEncryptable(array $columns): static
    {
        // normalize to plain column names (no table prefix)
        $this->encryptable = array_values(array_unique(array_map(function ($c) {
            return is_string($c) && str_contains($c, '.') ? last(explode('.', $c)) : (string) $c;
        }, $columns)));

        return $this;
    }

    /**
     * Get encrypted columns for this builder.
     *
     * @return array<string>
     */
    public function getEncryptable(): array
    {
        return $this->encryptable;
    }
}
