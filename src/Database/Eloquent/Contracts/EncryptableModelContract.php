<?php

namespace Thanous\AESEncrypt\Database\Eloquent\Contracts;

interface EncryptableModelContract
{
    /**
     * Return the list of attributes/columns that are stored encrypted.
     *
     * @return array<string>
     */
    public function getEncryptableAttributes(): array;
}
