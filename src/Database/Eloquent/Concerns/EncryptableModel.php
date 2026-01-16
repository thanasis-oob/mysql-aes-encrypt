<?php

namespace mrzainulabideen\AESEncrypt\Database\Eloquent\Concerns;

use mrzainulabideen\AESEncrypt\Contracts\EncryptableModelContract;
use mrzainulabideen\AESEncrypt\Database\Query\BuilderEncrypt;

trait EncryptableModel
{
    public function getEncryptableAttributes(): array
    {
        // Default: read from $fillableEncrypt property if present
        return property_exists($this, 'fillableEncrypt')
            ? array_values((array) $this->fillableEncrypt)
            : [];
    }

    protected function newBaseQueryBuilder()
    {
        $connection = $this->getConnection();

        $builder = new BuilderEncrypt(
            $connection,
            $connection->getQueryGrammar(),
            $connection->getPostProcessor()
        );

        $builder->setEncryptable($this->getEncryptableAttributes());

        return $builder;
    }
}
