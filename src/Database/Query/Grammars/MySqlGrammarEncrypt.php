<?php

namespace mrzainulabideen\AESEncrypt\Database\Query\Grammars;

use Illuminate\Contracts\Database\Query\Expression;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\Grammars\MySqlGrammar;
use Illuminate\Database\Query\JoinLateralClause;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use mrzainulabideen\AESEncrypt\Database\Query\BuilderEncrypt;
use Illuminate\Support\Str;

class MySqlGrammarEncrypt extends MySqlGrammar
{
    protected $columnsEncrypt = [];
    protected ?Builder $currentQuery = null;

    /* ------------------------------------------------------------
     | Helpers
     |------------------------------------------------------------ */

    protected function isEncryptedColumn(Builder $query, string $column): bool
    {
        if (!$query instanceof BuilderEncrypt) {
            return false;
        }

        return $query->isEncryptableColumn($column);
    }

    protected function isEncryptableBuilder(Builder $query): bool
    {
        return $query instanceof BuilderEncrypt;
    }

    /**
     * Convert given column name to the unqualified name.
     * ex. users.name -> name
     * ex. users.Name -> name
     *
     * @param string $column
     *
     * @return string
     */
    protected function toUnqualifiedColumn(string $column): string
    {
        return Str::lower(Arr::last(explode('.', $column)));
    }

    protected function decryptColumn(string $column): string
    {
        return EncryptExpressions::decrypt($column);
    }

    /**
     * Compile an insert statement into SQL.
     *
     * @param \Illuminate\Database\Query\Builder $query
     * @param array $values
     *
     * @return string
     */
    public function compileInsert(Builder $query, array $values)
    {
        if (empty($values) || !$this->isEncryptableBuilder($query)) {
            return parent::compileInsert($query, $values);
        }

        /** @var BuilderEncrypt $query */
        $encryptedColumns = $query->getEncryptable();

        // Essentially we will force every insert to be treated as a batch insert which
        // simply makes creating the SQL easier for us since we can utilize the same
        // basic routine regardless of an amount of records given to us to insert.
        $table = $this->wrapTable($query->from);

//        if (empty($values)) {
//            return "insert into {$table} default values";
//        }

        if (!is_array(reset($values))) {
            $values = [$values];
        }

        //should not encrpyt/decrypt insert column names
        $columns = $this->columnize(array_keys(reset($values)));

        // We need to build a list of parameter place-holders of values that are bound
        // to the query. Each insert should have the exact same number of parameter
        // bindings so we will loop through the record and parameterize them all.
        $parameters = (new Collection($values))->map(function ($record) use ($encryptedColumns) {
            return '(' . $this->parameterize($record, $encryptedColumns) . ')';
        })->implode(', ');

        return "insert into $table ($columns) values $parameters";
    }

    /**
     * Compile a select query into SQL.
     *
     * @param \Illuminate\Database\Query\Builder $query
     *
     * @return string
     */
    public function compileSelect(Builder $query)
    {
        if (!$this->isEncryptableBuilder($query)) {
            return parent::compileSelect($query);
        }
        /** @var BuilderEncrypt $query */
        $encryptedColumns = $query->getEncryptable();

        if (($query->unions || $query->havings) && $query->aggregate) {
            return $this->compileUnionAggregate($query);
        }

        // If a "group limit" is in place, we will need to compile the SQL to use a
        // different syntax. This primarily supports limits on eager loads using
        // Eloquent. We'll also set the columns if they have not been defined.
        if (isset($query->groupLimit)) {
            if (is_null($query->columns)) {
                $query->columns = ['*'];
            }

            return $this->compileGroupLimit($query);
        }

        // If the query does not have any columns set, we'll set the columns to the
        // * character to just get all of the columns from the database. Then we
        // can build the query and concatenate all the pieces together as one.
        $original = $query->columns;

        if (is_null($query->columns)) {
            $query->columns = ['*'];
        }

        // To compile the query, we'll spin through each component of the query and
        // see if that component exists. If it does we'll just call the compiler
        // function for the component which is responsible for making the SQL.
        $sql = trim($this->concatenate(
            $this->compileComponents($query))
        );

        if ($query->unions) {
            $sql = $this->wrapUnion($sql) . ' ' . $this->compileUnions($query);
        }

        $query->columns = $original;

//        dd($sql);
        return $sql;
    }

    protected function compileColumns(Builder $query, $columns)
    {
        if (!$this->isEncryptableBuilder($query)) {
            return parent::compileColumns($query, $columns);
        }
        /** @var BuilderEncrypt $query */
        $encryptedColumns = $query->getEncryptable();

        // If the query is actually performing an aggregating select, we will let that
        // compiler handle the building of the select clauses, as it will need some
        // more syntax that is best handled by that function to keep things neat.
        if (!is_null($query->aggregate)) {
            return;
        }

        if ($query->distinct) {
            $select = 'select distinct ';
        } else {
            $select = 'select ';
        }

        return $select . $this->columnize($columns, $encryptedColumns);
    }

    /**
     * Compile the columns for an update statement.
     *
     * @param \Illuminate\Database\Query\Builder $query
     * @param array $values
     *
     * @return string
     */
    protected function compileUpdateColumns(Builder $query, array $values)
    {
        if (!$this->isEncryptableBuilder($query)) {
            return parent::compileUpdateColumns($query, $values);
        }
        /** @var BuilderEncrypt $query */
        $encryptedColumns = $query->getEncryptable();

        return (new Collection($values))->map(function ($value, $columnName) use ($encryptedColumns) {
            if ($this->isJsonSelector($columnName)) {
                return $this->compileJsonUpdateColumn($columnName, $value, $encryptedColumns);
            }

            $unqualifiedColumnName = $this->toUnqualifiedColumn($columnName);
            $parameter = $this->parameter($value);
            if (!empty($encryptedColumns) && in_array($unqualifiedColumnName, $encryptedColumns, true)) {
                $parameter = EncryptExpressions::encrypt($parameter);
            }

            return $this->wrap($columnName) . ' = ' . $parameter;
        })->implode(', ');
    }

    /**
     * Convert an array of column names into a delimited string.
     *
     * @param array $columns
     * @param array $encryptable
     *
     * @return string
     */
    public function columnize(array $columns, array $encryptable = [])
    {
        $columnizeColumns = [];

        $columns = $this->addColumnsToWildcard($columns, $encryptable);


        foreach ($columns as $column) {
//            dump($column);
            $unqualifiedColumnName = $this->toUnqualifiedColumn($column);
            $wrappedColumn = $this->wrap($column, $encryptable);
//            dump($wrappedColumn);

            if (true
                && in_array($unqualifiedColumnName, $encryptable)
                && strpos(strtolower($wrappedColumn), ' as ') === false
                && strpos(strtolower($wrappedColumn), '*') === false) {
                preg_match_all("/\`.*?\`/", $wrappedColumn, $alias);
                $wrappedColumn = $wrappedColumn . ' as ' . Arr::last($alias[0]);
//                dump($alias);
//                dump(Arr::last($alias[0]));
//                dd($wrappedColumn);
            }

            $columnizeColumns[] = $wrappedColumn;
        }

//        dd($columnizeColumns);

        return implode(', ', $columnizeColumns);
    }

    /**
     * if columns only contain a wildcard we add the encrypted columns to decrypt
     *
     * @param array $columns
     * @param array $columnsEncrypt
     *
     * @return array
     */
    public function addColumnsToWildcard(array $columns, array $columnsEncrypt)
    {
        if (!empty($columns) && strpos(strtolower($columns[0]), '*') !== false) {
            $columns = array_merge($columns, $columnsEncrypt);
        }
        return $columns;
    }

    /**
     * Create query parameter place-holders for an array.
     *
     * @param array $values
     * @param array $encryptable
     *
     * @return string
     */
    public function parameterize(array $values, array $encryptable = [])
    {
        return (new Collection($values))->map(function ($columnValue, $columnName) use ($encryptable) {
            $parameter = $this->parameter($columnName);
            if (!empty($encryptable) && in_array($columnName, $encryptable, true)) {
                $parameter = EncryptExpressions::encrypt($parameter);
            }
            return $parameter;
        })->implode(', ');
    }

    /**
     * Wrap a value in keyword identifiers.
     *
     * @param Expression|string $value
     * @param array $encryptable
     *
     * @return string
     */
    public function wrap($value, array $encryptable = [])
    {
        if (empty($encryptable)) {
            return parent::wrap($value);
        }

        if ($this->isExpression($value)) {
            return $this->getValue($value);
        }

        // If the value being wrapped has a column alias we will need to separate out
        // the pieces so we can wrap each of the segments of the expression on its
        // own, and then join these both back together using the "as" connector.
        if (stripos($value, ' as ') !== false) {
            return $this->wrapAliasedValue($value, $encryptable);
        }

        // If the given value is a JSON selector we will wrap it differently than a
        // traditional value. We will need to split this path and wrap each part
        // wrapped, etc. Otherwise, we will simply wrap the value as a string.
        /* @todo Need encryption handling */
        if ($this->isJsonSelector($value)) {
            return $this->wrapJsonSelector($value);
        }

        return $this->wrapSegments(explode('.', $value), $encryptable);
    }


    /**
     * Wrap a value that has an alias.
     *
     * @param string $value
     * @param array $encryptable
     *
     * @return string
     */
    protected function wrapAliasedValue($value, array $encryptable = [])
    {
        $segments = preg_split('/\s+as\s+/i', $value);

        return $this->wrap($segments[0], $encryptable) . ' as ' . $this->wrapValue($segments[1]);
    }

    /**
     * Split the given JSON selector into the field and the optional path and wrap them separately.
     *
     * @param string $column
     * @param array $encryptable
     *
     * @return array
     */
    protected function wrapJsonFieldAndPath($column, array $encryptable = [])
    {
        $parts = explode('->', $column, 2);

        $field = $this->wrap($parts[0], $encryptable);

        $path = count($parts) > 1 ? ', ' . $this->wrapJsonPath($parts[1], '->') : '';

        return [$field, $path];
    }

    /**
     * Wrap the given value segments.
     *
     * @param $segments
     * @param array $encryptable
     *
     * @return string
     */
    protected function wrapSegments($segments, array $encryptable = [])
    {
        $wrapped = (new Collection($segments))->map(function ($segment, $key) use ($segments) {
            return $key == 0 && count($segments) > 1
                ? $this->wrapTable($segment)
                : $this->wrapValue($segment);
        })->implode('.');

        return in_array(strtolower(Arr::last($segments)), $encryptable, true)
            ? $this->decryptColumn($wrapped, $encryptable)
            : $wrapped;
    }

    /**
     * @param $value
     * @param array $encryptable
     *
     * @return string
     */
    protected function wrapValue($value, array $encryptable = [])
    {
        if ($value === '*') {
            return $value;
        }
        $wrapped = '`' . str_replace('`', '``', $value) . '`';
        if (in_array($value, $encryptable)) {
            return $this->decryptColumn($wrapped);
        }

        return $wrapped;
    }
}
