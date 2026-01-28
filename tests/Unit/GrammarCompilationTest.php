<?php

namespace Thanous\AESEncrypt\Tests\Unit;

use Illuminate\Database\Query\Expression;
use Thanous\AESEncrypt\AesConfig;
use Thanous\AESEncrypt\Tests\TestCase;

class GrammarCompilationTest extends TestCase
{
    public function test_select_encryptable_column_is_decrypted_and_auto_aliased(): void
    {
        $q = $this->makeEncryptBuilder(['email'])->from('users')->select(['email']);

        $sql = $this->norm($q->toSql());

        $this->assertStringContainsString(
            'select CONVERT(AES_DECRYPT(`email`, @AESKEY) USING utf8mb4) as `email` from `users`',
            $sql
        );
    }

    public function test_select_qualified_encryptable_column_is_decrypted_and_aliased_to_unqualified(): void
    {
        $q = $this->makeEncryptBuilder(['email'])->from('users')->select(['users.email']);

        $sql = $this->norm($q->toSql());

        $this->assertStringContainsString(
            'select CONVERT(AES_DECRYPT(`users`.`email`, @AESKEY) USING utf8mb4) as `email` from `users`',
            $sql
        );
    }

    public function test_select_encryptable_column_with_explicit_alias_keeps_alias(): void
    {
        $q = $this->makeEncryptBuilder(['email'])->from('users')->select(['email as e']);

        $sql = $this->norm($q->toSql());

        $this->assertStringContainsString(
            'select CONVERT(AES_DECRYPT(`email`, @AESKEY) USING utf8mb4) as `e` from `users`',
            $sql
        );
    }

    public function test_select_wildcard_adds_encryptable_columns_and_auto_aliases(): void
    {
        $q = $this->makeEncryptBuilder(['email'])->from('users')->select(['*']);

        $sql = $this->norm($q->toSql());

        $this->assertStringContainsString('select *,', $sql);
        $this->assertStringContainsString('AES_DECRYPT(`email`, @AESKEY)', $sql);
        $this->assertStringContainsString('as `email`', $sql);
        $this->assertSame(1, substr_count($sql, 'AES_DECRYPT(`email`'));
    }

    public function test_select_with_expressions_columns(): void
    {
        $q = $this->makeEncryptBuilder(['email'])->from('users')
            ->select(['*', 'name', new Expression('LENGTH(email)')]);

        $sql = $this->norm($q->toSql());

        $this->assertStringContainsString('AES_DECRYPT(`email`, @AESKEY)', $sql);
        $this->assertStringNotContainsString('AES_DECRYPT(LENGTH(', $sql);
    }

    public function test_where_basic_decrypts_column_and_keeps_placeholder(): void
    {
        $q = $this->makeEncryptBuilder(['email'])->from('users')->where('email', '=', 'a@b.com');

        $sql = $this->norm($q->toSql());

        $this->assertStringContainsString(
            'where CONVERT(AES_DECRYPT(`email`, @AESKEY) USING utf8mb4) = ?',
            $sql
        );
        $this->assertSame(['a@b.com'], $q->getBindings());
    }

    public function test_where_in_decrypts_column(): void
    {
        $q = $this->makeEncryptBuilder(['email'])->from('users')
            ->whereIn('email', ['a@b.com', 'c@d.com']);

        $sql = $this->norm($q->toSql());

        $this->assertStringContainsString(
            'where CONVERT(AES_DECRYPT(`email`, @AESKEY) USING utf8mb4) in (?, ?)',
            $sql
        );
    }

    public function test_where_not_in_decrypts_column(): void
    {
        $q = $this->makeEncryptBuilder(['email'])->from('users')
            ->whereNotIn('email', ['a@b.com']);

        $sql = $this->norm($q->toSql());

        $this->assertStringContainsString(
            'where CONVERT(AES_DECRYPT(`email`, @AESKEY) USING utf8mb4) not in (?)',
            $sql
        );
    }

    public function test_where_between_decrypts_column(): void
    {
        $q = $this->makeEncryptBuilder(['email'])->from('users')
            ->whereBetween('email', ['a', 'z']);

        $sql = $this->norm($q->toSql());

        $this->assertStringContainsString(
            'where CONVERT(AES_DECRYPT(`email`, @AESKEY) USING utf8mb4) between ? and ?',
            $sql
        );
    }

    public function test_where_between_columns_decrypts_min_max_if_encryptable(): void
    {
        $q = $this->makeEncryptBuilder(['email', 'email2'])->from('users')
            ->whereBetweenColumns('email', ['email2', 'email2']);

        $sql = $this->norm($q->toSql());

        $this->assertStringContainsString('between', $sql);
        $this->assertStringContainsString('AES_DECRYPT(`email`', $sql);
        $this->assertStringContainsString('AES_DECRYPT(`email2`', $sql);
    }

    public function test_where_column_decrypts_both_sides_if_encryptable(): void
    {
        $q = $this->makeEncryptBuilder(['email', 'email2'])->from('users')
            ->whereColumn('email', '=', 'email2');

        $sql = $this->norm($q->toSql());

        $this->assertStringContainsString('AES_DECRYPT(`email`', $sql);
        $this->assertStringContainsString('AES_DECRYPT(`email2`', $sql);
    }

    public function test_where_row_values_decrypts_encryptable_columns(): void
    {
        $q = $this->makeEncryptBuilder(['email'])->from('users')
            ->whereRowValues(['email', 'name'], '=', ['a@b.com', 'John']);

        $sql = $this->norm($q->toSql());

        $this->assertStringContainsString(
            '(CONVERT(AES_DECRYPT(`email`, @AESKEY) USING utf8mb4), `name`) = (?, ?)',
            $sql
        );
    }

    public function test_where_date_based_decrypts_column(): void
    {
        $q = $this->makeEncryptBuilder(['email'])->from('users')
            ->whereDate('email', '=', '2026-01-01');

        $sql = $this->norm($q->toSql());

        $this->assertStringContainsString(
            'date(CONVERT(AES_DECRYPT(`email`, @AESKEY) USING utf8mb4)) = ?',
            $sql
        );
    }

    public function test_order_by_decrypts_encryptable_column(): void
    {
        $q = $this->makeEncryptBuilder(['email'])->from('users')->orderBy('email', 'asc');

        $sql = $this->norm($q->toSql());

        $this->assertStringContainsString(
            'order by CONVERT(AES_DECRYPT(`email`, @AESKEY) USING utf8mb4) asc',
            $sql
        );
    }

    public function test_group_by_decrypts_encryptable_column(): void
    {
        $q = $this->makeEncryptBuilder(['email'])->from('users')->groupBy('email');

        $sql = $this->norm($q->toSql());

        $this->assertStringContainsString(
            'group by CONVERT(AES_DECRYPT(`email`, @AESKEY) USING utf8mb4)',
            $sql
        );
    }

    public function test_having_basic_decrypts_encryptable_column(): void
    {
        $q = $this->makeEncryptBuilder(['email'])->from('users')
            ->groupBy('email')
            ->having('email', '!=', 'x');

        $sql = $this->norm($q->toSql());

        $this->assertStringContainsString(
            'having CONVERT(AES_DECRYPT(`email`, @AESKEY) USING utf8mb4) != ?',
            $sql
        );
    }

    public function test_insert_encrypts_encryptable_values(): void
    {
        $q = $this->makeEncryptBuilder(['email'])->from('users');

        $sql = $this->norm($q->grammar->compileInsert($q, [
            ['name' => 'John', 'email' => 'a@b.com'],
        ]));

        $this->assertStringContainsString(
            'insert into `users` (`name`, `email`) values (?, AES_ENCRYPT(?, @AESKEY))',
            $sql
        );
    }

    public function test_update_encrypts_only_encryptable_columns_sql_only(): void
    {
        $q = $this->makeEncryptBuilder(['email'])->from('users')->where('id', 1);

        $sql = $this->norm($q->grammar->compileUpdate($q, [
            'email' => 'a@b.com',
            'name' => 'John',
        ]));

        $this->assertStringContainsString(
            'update `users` set `email` = AES_ENCRYPT(?, @AESKEY), `name` = ? where `id` = ?',
            $sql
        );
    }

    public function test_upsert_encrypts_assoc_update_values(): void
    {
        $q = $this->makeEncryptBuilder(['email'])->from('users');

        $sql = $this->norm($q->grammar->compileUpsert(
            $q,
            [['id' => 1, 'email' => 'a@b.com']],
            ['id'],
            ['email' => 'x@x.com']
        ));

        $this->assertStringContainsString('on duplicate key update', $sql);
        $this->assertStringContainsString('`email` = AES_ENCRYPT(?, @AESKEY)', $sql);
    }

    public function test_json_selector_is_not_decrypted(): void
    {
        $q = $this->makeEncryptBuilder(['profile'])->from('users')->select(['profile->name']);

        $sql = $this->norm($q->toSql());

        $this->assertStringContainsString('json_unquote(json_extract(', $sql);
        $this->assertStringNotContainsString('AES_DECRYPT', $sql);
    }

    public function test_group_limit_throws(): void
    {
        $q = $this->makeEncryptBuilder(['email'])->from('users');
        $q->groupLimit = ['column' => 'users.id', 'value' => 1];

        $this->expectException(\RuntimeException::class);
        $q->toSql();
    }

    public function test_non_encryptable_builder_has_no_aes_expressions(): void
    {
        $q = $this->makePlainBuilder()->from('users')->select(['email'])->where('email', 'a@b.com');

        $sql = $this->norm($q->toSql());

        $this->assertStringNotContainsString('AES_', $sql);
        $this->assertStringNotContainsString('AES_DECRYPT', $sql);
    }

    public function test_iv_mode_changes_decrypt_expression_shape(): void
    {
        AesConfig::set('test-key', 'aes-256-cbc', true, true);

        $q = $this->makeEncryptBuilder(['email'])->from('users')->select(['email']);

        $sql = $this->norm($q->toSql());

        $this->assertStringContainsString('SUBSTRING_INDEX(`email`, \'.iv.\', 1)', $sql);
        $this->assertStringContainsString('SUBSTRING_INDEX(`email`, \'.iv.\', -1)', $sql);
    }

    public function test_insert_does_not_encrypt_null_encryptable_value(): void
    {
        $q = $this->makeEncryptBuilder(['email'])->from('users');

        $sql = $this->norm($q->grammar->compileInsert($q, [
            ['name' => 'John', 'email' => null],
        ]));

        // email should NOT be wrapped in AES_ENCRYPT
        $this->assertStringContainsString(
            'insert into `users` (`name`, `email`) values (?, ?)',
            $sql
        );
        $this->assertStringNotContainsString('AES_ENCRYPT', $sql);
    }

    public function test_update_does_not_encrypt_null_encryptable_value(): void
    {
        $q = $this->makeEncryptBuilder(['email'])->from('users')->where('id', 1);

        $sql = $this->norm($q->grammar->compileUpdate($q, [
            'email' => null,
        ]));

        $this->assertStringContainsString(
            'update `users` set `email` = ? where `id` = ?',
            $sql
        );
        $this->assertStringNotContainsString('AES_ENCRYPT', $sql);
    }

    public function test_where_null_does_not_decrypt_or_encrypt(): void
    {
        $q = $this->makeEncryptBuilder(['email'])->from('users')->whereNull('email');

        $sql = $this->norm($q->toSql());
        $this->assertStringContainsString('where `email` is null', $sql);
    }

    public function test_where_not_null_does_not_decrypt_or_encrypt(): void
    {
        $q = $this->makeEncryptBuilder(['email'])->from('users')->whereNotNull('email');

        $sql = $this->norm($q->toSql());

        $this->assertStringContainsString('where `email` is not null', $sql);
    }

    public function test_select_star_does_not_duplicate_encryptable_columns(): void
    {
        $q = $this->makeEncryptBuilder(['email', 'name', 'phone'])
            ->from('users')
            ->select(['*', 'email', 'users.name as myName'
//                , 'users.email', 'email as e', 'name'
            ]);

        $sql = $this->norm($q->toSql());

        // ensure "email as `email`" appears only once (auto-alias case)
        $this->assertSame(1, preg_match_all(
            '/\bas\s+`email`/i',
            $sql
        ));

        // ensure decrypted name expression appears only once (regardless of aliasing)
        //___CONVERT(AES_DECRYPT(`users`.`name`, @AESKEY) USING utf8mb4) as `myName`
        $this->assertSame(1, preg_match_all(
            '/CONVERT\(\s*AES_DECRYPT\(`(?:users`\.`)?name`,\s*@AESKEY\)\s*USING\s+utf8mb4\s*\)\s+as\s+`myName`/i',
            $sql
        ));

        // ensure decrypted name expression appears only once
        $this->assertSame(1, preg_match_all(
            '/CONVERT\(\s*AES_DECRYPT\(`phone`,\s*@AESKEY\)\s*USING\s+utf8mb4\s*\)/i',
            $sql
        ));
    }
}
