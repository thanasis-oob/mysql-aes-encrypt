<?php

namespace mrzainulabideen\AESEncrypt\Database\Eloquent;

use Illuminate\Database\Eloquent\Model;
use mrzainulabideen\AESEncrypt\Database\Query\BuilderEncrypt;

/**
 * Extend this model for encryption support.
 *
 * Usage:
 *   class User extends \mrzainulabideen\AESEncrypt\Database\Eloquent\ModelEncrypt
 *   {
 *       protected array $fillableEncrypt = ['first_name'];
 *   }
 */
abstract class ModelEncrypt extends Model
{
    /**
     * Columns that should be encrypted in DB and decrypted in queries.
     *
     * @var array<string>
     */
    protected array $fillableEncrypt = [];

    /**
     * Use our custom query builder that carries the encryptable columns.
     */
    protected function newBaseQueryBuilder()
    {
        $connection = $this->getConnection();

        /** @var \mrzainulabideen\AESEncrypt\Database\Query\BuilderEncrypt $builder */
        $builder = new BuilderEncrypt(
            $connection,
            $connection->getQueryGrammar(),
            $connection->getPostProcessor()
        );

        $builder->setEncryptable($this->fillableEncrypt);

        return $builder;
    }
}
