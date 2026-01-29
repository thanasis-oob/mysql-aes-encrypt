<?php

namespace Thanous\AESEncrypt\Tests\Unit;

use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\Test;
use Thanous\AESEncrypt\AesConfig;
use Thanous\AESEncrypt\Database\Eloquent\Concerns\EncryptableModel;
use Thanous\AESEncrypt\Database\Query\BuilderEncrypt;
use Thanous\AESEncrypt\Tests\TestCase;

final class EncryptableModelTest extends TestCase
{
    private function makeModel(Connection $conn): Model
    {
        $model = new class extends Model {
            use EncryptableModel;

            protected $table = 'users';
            protected $encryptable = ['email'];

            protected ?Connection $testConnection = null;

            // Must remain compatible with Eloquent internals (new static)
            public function __construct(array $attributes = [])
            {
                parent::__construct($attributes);
            }

            public function setTestConnection(Connection $conn): void
            {
                $this->testConnection = $conn;
            }

            public function getConnection()
            {
                return $this->testConnection ?? parent::getConnection();
            }
        };

        $model->setTestConnection($conn);

        return $model;
    }

    #[Test]
    public function it_uses_parent_query_builder_when_key_is_empty(): void
    {
        AesConfig::set('', 'aes-256-cbc', false, true);

        $conn = $this->makeFakeConnection();
        $model = $this->makeModel($conn);

        $builder = $model->newQuery()->getQuery();

        $this->assertNotInstanceOf(BuilderEncrypt::class, $builder);
    }

    #[Test]
    public function it_uses_encrypt_builder_when_key_is_present(): void
    {
        AesConfig::set('test-key', 'aes-256-cbc', false, true);

        $conn = $this->makeFakeConnection();
        $model = $this->makeModel($conn);

        $builder = $model->newQuery()->getQuery();

        $this->assertInstanceOf(BuilderEncrypt::class, $builder);
        $this->assertSame(['email'], $builder->getEncryptable());
    }
}
