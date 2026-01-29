<?php

namespace Thanous\AESEncrypt\Database\Eloquent\Concerns;

use Thanous\AESEncrypt\AesConfig;
use Thanous\AESEncrypt\Database\Query\BuilderEncrypt;

trait EncryptableModel
{
    public function getEncryptableAttributes(): array
    {
        return property_exists($this, 'encryptable')
            ? array_values((array) $this->encryptable)
            : [];
    }

    protected function newBaseQueryBuilder()
    {
        if (!AesConfig::canApplyEncryptionGrammar()) {
            return parent::newBaseQueryBuilder();
        }

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
