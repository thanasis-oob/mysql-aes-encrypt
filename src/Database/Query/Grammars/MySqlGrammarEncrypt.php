<?php

namespace Thanous\AESEncrypt\Database\Query\Grammars;

use Illuminate\Contracts\Database\Query\Expression;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\Grammars\MySqlGrammar;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use Thanous\AESEncrypt\Database\Query\BuilderEncrypt;
use RuntimeException;

class MySqlGrammarEncrypt extends MySqlGrammar
{
    /* ------------------------------------------------------------
     | Helpers
     |------------------------------------------------------------ */

    /**
     * @param $columnName
     * @param array $encryptableColumns
     *
     * @return bool
     */
    public function isEncryptableColumn($columnName, array $encryptableColumns = []): bool
    {
        $unqualifiedColumnName = $this->toUnqualifiedColumn($columnName);
        return !empty($encryptableColumns) && in_array($unqualifiedColumnName, $encryptableColumns, true);
    }

    /**
     *
     * @param $column
     *
     * @return bool
     */
    public function isAliasedColumn($column): bool
    {
        return stripos($column, ' as ') !== false;
    }

    /**
     *
     * @param $column
     *
     * @return bool
     */
    public function removeColumnAlias($column): string
    {
        $column = str_replace(' AS', ' as ', $column);
        return Arr::first(explode(' as ', $column));
    }

    /**
     * @param Builder $query
     *
     * @return bool
     */
    protected function isEncryptableBuilder(Builder $query): bool
    {
        return $query instanceof BuilderEncrypt;
    }

    /**
     * Convert given column name to the unqualified name.
     *
     *  ex. name -> name
     *  ex. NAME -> name
     * ex. users.name -> name
     * ex. users.NAME -> name
     *
     * @param string $column
     *
     * @return string
     */
    protected function toUnqualifiedColumn($column)
    {
        //split alias
        if ($this->isExpression($column)) {
            return $column;
        }

        //split alias
        if($this->isAliasedColumn($column)) {
            $column = $this->removeColumnAlias($column);
        }
        return Str::lower(Arr::last(explode('.', $column)));
    }

    /**
     * Create the decrypted column mysql expression.
     *
     * @param string $column
     *
     * @return string
     */
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
            return parent::{__FUNCTION__}(...func_get_args());
        }

        /** @var BuilderEncrypt $query */
        $encryptableColumns = $query->getEncryptable();

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

        //should not encrypt/decrypt insert column names
        $columns = $this->columnize(array_keys(reset($values)));

        // We need to build a list of parameter place-holders of values that are bound
        // to the query. Each insert should have the exact same number of parameter
        // bindings so we will loop through the record and parameterize them all.
        $parameters = (new Collection($values))->map(function ($record) use ($encryptableColumns) {
            return '(' . $this->parameterize($record, $encryptableColumns) . ')';
        })->implode(', ');

        return "insert into $table ($columns) values $parameters";
    }

    /**
     * Compile an aggregated select clause.
     *
     * @param \Illuminate\Database\Query\Builder $query
     * @param array $aggregate
     *
     * @return string
     */
    protected function compileAggregate(Builder $query, $aggregate)
    {
        if (!$this->isEncryptableBuilder($query)) {
            return parent::{__FUNCTION__}(...func_get_args());
        }
        /** @var BuilderEncrypt $query */
        $encryptableColumns = $query->getEncryptable();
//        $encryptableColumns = $query->getEncryptable();
        // usually the aggregate column is * or a column nad combination of * and a specific column
        // so, we check if the first column is * to skip encryption
        if(str_contains(Arr::get($aggregate['columns'], 0), '*')) {
            // if aggregate columns is '*', we should not append the encryptable columns
            $column = $this->columnize($aggregate['columns'], [], false);
        } else {
            $column = $this->columnize($aggregate['columns'], $encryptableColumns, false);
        }

        // If the query has a "distinct" constraint, and we're not asking for all columns
        // we need to prepend "distinct" onto the column name so that the query takes
        // it into account when it performs the aggregating operations on the data.
        if (is_array($query->distinct)) {
            $column = 'distinct ' . $this->columnize($query->distinct, $encryptableColumns);
        } elseif ($query->distinct && $column !== '*') {
            $column = 'distinct ' . $column;
        }

        return 'select ' . $aggregate['function'] . '(' . $column . ') as aggregate';
    }

    /**
     * Compile the "group by" portions of the query.
     *
     * @param \Illuminate\Database\Query\Builder $query
     * @param array $groups
     *
     * @return string
     */
    protected function compileGroups(Builder $query, $groups)
    {
        if (!$this->isEncryptableBuilder($query)) {
            return parent::{__FUNCTION__}(...func_get_args());
        }
        /** @var BuilderEncrypt $query */
        $encryptableColumns = $query->getEncryptable();

        return 'group by ' . $this->columnize($groups, $encryptableColumns, false);
    }

    /**
     * Compile the "having" portions of the query.
     *
     * @param \Illuminate\Database\Query\Builder $query
     *
     * @return string
     */
    protected function compileHavings(Builder $query)
    {
        if (!$this->isEncryptableBuilder($query)) {
            return parent::{__FUNCTION__}(...func_get_args());
        }
        /** @var BuilderEncrypt $query */
        $encryptableColumns = $query->getEncryptable();

        return 'having ' . $this->removeLeadingBoolean((new Collection($query->havings))->map(function ($having) use ($encryptableColumns) {
                return $having['boolean'] . ' ' . $this->compileHaving($having, $encryptableColumns);
            })->implode(' '));
    }

    /**
     * Compile a single having clause.
     *
     * @param array $having
     * @param array $encryptableColumns
     *
     * @return string
     */
    protected function compileHaving(array $having, array $encryptableColumns = [])
    {
        // If the having clause is "raw", we can just return the clause straight away
        // without doing any more processing on it. Otherwise, we will compile the
        // clause into SQL based on the components that make it up from builder.
        return match ($having['type']) {
            'Raw' => $having['sql'],
            'between' => $this->compileHavingBetween($having, $encryptableColumns),
            'Null' => $this->compileHavingNull($having, $encryptableColumns),
            'NotNull' => $this->compileHavingNotNull($having, $encryptableColumns),
            'bit' => $this->compileHavingBit($having, $encryptableColumns),
            'Expression' => $this->compileHavingExpression($having, $encryptableColumns),
            'Nested' => $this->compileNestedHavings($having, $encryptableColumns),
            default => $this->compileBasicHaving($having, $encryptableColumns),
        };
    }

    /**
     * Compile a basic having clause.
     *
     * @param array $having
     * @param array $encryptableColumns
     *
     * @return string
     */
    protected function compileBasicHaving($having, array $encryptableColumns = [])
    {
        $column = $this->wrap($having['column'], $encryptableColumns);

        $parameter = $this->parameter($having['value']);

        return $column . ' ' . $having['operator'] . ' ' . $parameter;
    }

    /**
     * Compile a "between" having clause.
     *
     * @param array $having
     * @param array $encryptableColumns
     *
     * @return string
     */
    protected function compileHavingBetween($having, array $encryptableColumns = [])
    {
        $between = $having['not'] ? 'not between' : 'between';

        $column = $this->wrap($having['column'], $encryptableColumns);

        $min = $this->parameter(head($having['values']));

        $max = $this->parameter(last($having['values']));

        return $column . ' ' . $between . ' ' . $min . ' and ' . $max;
    }

    /**
     * Compile a having clause involving a bit operator.
     *
     * @param array $having
     * @param array $encryptableColumns
     *
     * @return string
     */
    protected function compileHavingBit($having, array $encryptableColumns = [])
    {
        $column = $this->wrap($having['column'], $encryptableColumns);

        $parameter = $this->parameter($having['value']);

        return '(' . $column . ' ' . $having['operator'] . ' ' . $parameter . ') != 0';
    }

    /**
     * Compile the query orders to an array.
     *
     * @param \Illuminate\Database\Query\Builder $query
     * @param array $orders
     *
     * @return array
     */
    protected function compileOrdersToArray(Builder $query, $orders)
    {
        if (!$this->isEncryptableBuilder($query)) {
            return parent::{__FUNCTION__}(...func_get_args());
        }
        /** @var BuilderEncrypt $query */
        $encryptableColumns = $query->getEncryptable();

        return array_map(function ($order) use ($encryptableColumns) {
            return $order['sql'] ?? $this->wrap($order['column'], $encryptableColumns) . ' ' . $order['direction'];
        }, $orders);
    }

    /**
     * Compile a group limit clause.
     *
     * @param \Illuminate\Database\Query\Builder $query
     *
     * @return string
     */
    protected function compileGroupLimit(Builder $query)
    {
        throw new RuntimeException('groupLimit() is not implemented.');

//        if (!$this->isEncryptableBuilder($query)) {
//            return parent::{__FUNCTION__}(...func_get_args());
//        }
//        /** @var BuilderEncrypt $query */
//        $encryptableColumns = $query->getEncryptable();
//
//        if ($this->useLegacyGroupLimit($query)) {
//            return $this->compileLegacyGroupLimit($query);
//        }
//
//        $selectBindings = array_merge($query->getRawBindings()['select'], $query->getRawBindings()['order']);
//
//        $query->setBindings($selectBindings, 'select');
//        $query->setBindings([], 'order');
//
//        $limit = (int) $query->groupLimit['value'];
//        $offset = $query->offset;
//
//        if (isset($offset)) {
//            $offset = (int) $offset;
//            $limit += $offset;
//
//            $query->offset = null;
//        }
//
//        $components = $this->compileComponents($query);
//
//        $components['columns'] .= $this->compileRowNumber(
//            $query->groupLimit['column'],
//            $components['orders'] ?? ''
//        );
//
//        unset($components['orders']);
//
//        $table = $this->wrap('laravel_table');
//        $row = $this->wrap('laravel_row');
//
//        $sql = $this->concatenate($components);
//
//        $sql = 'select * from ('.$sql.') as '.$table.' where '.$row.' <= '.$limit;
//
//        if (isset($offset)) {
//            $sql .= ' and '.$row.' > '.$offset;
//        }
//
//        return $sql.' order by '.$row;
    }

    /**
     * Compile the "select *" portion of the query.
     *
     * @param \Illuminate\Database\Query\Builder $query
     * @param array $columns
     *
     * @return string|null
     */
    protected function compileColumns(Builder $query, $columns)
    {
        if (!$this->isEncryptableBuilder($query)) {
            return parent::{__FUNCTION__}(...func_get_args());
        }
        /** @var BuilderEncrypt $query */
        $encryptableColumns = $query->getEncryptable();

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

        return $select . $this->columnize($columns, $encryptableColumns);
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
            return parent::{__FUNCTION__}(...func_get_args());
        }
        /** @var BuilderEncrypt $query */
        $encryptableColumns = $query->getEncryptable();

        return (new Collection($values))->map(function ($value, $columnName) use ($encryptableColumns) {
            if ($this->isJsonSelector($columnName)) {
                return $this->compileJsonUpdateColumn($columnName, $value);
            }

            $parameter = $this->parameter($value);
            if (!is_null($value) && $this->isEncryptableColumn($columnName, $encryptableColumns)) {
                $parameter = EncryptExpressions::encrypt($parameter);
            }

            return $this->wrap($columnName) . ' = ' . $parameter;
        })->implode(', ');
    }

    /**
     * Compile an "upsert" statement into SQL.
     *
     * @param \Illuminate\Database\Query\Builder $query
     * @param array $values
     * @param array $uniqueBy
     * @param array $update
     *
     * @return string
     */
    public function compileUpsert(Builder $query, array $values, array $uniqueBy, array $update)
    {
        if (!$this->isEncryptableBuilder($query)) {
            return parent::{__FUNCTION__}(...func_get_args());
        }
        /** @var BuilderEncrypt $query */
        $encryptableColumns = $query->getEncryptable();

        $useUpsertAlias = $query->connection->getConfig('use_upsert_alias');

        $sql = $this->compileInsert($query, $values);

        if ($useUpsertAlias) {
            $sql .= ' as laravel_upsert_alias';
        }

        $sql .= ' on duplicate key update ';


        $columns = (new Collection($update))->map(function ($value, $key) use ($useUpsertAlias, $encryptableColumns) {
            if (!is_numeric($key)) {
                $parameter = $this->parameter($value);
                if ($this->isEncryptableColumn($key, $encryptableColumns)) {
                    $parameter = EncryptExpressions::encrypt($parameter);
                }
                return $this->wrap($key) . ' = ' . $parameter;
            }

            return $useUpsertAlias
                ? $this->wrap($value) . ' = ' . $this->wrap('laravel_upsert_alias') . '.' . $this->wrap($value)
                : $this->wrap($value) . ' = values(' . $this->wrap($value) . ')';
        })->implode(', ');

        return $sql . $columns;
    }

    /**
     * Compile a basic where clause.
     *
     * @param \Illuminate\Database\Query\Builder $query
     * @param array $where
     *
     * @return string
     */
    protected function whereBasic(Builder $query, $where)
    {
        if (!$this->isEncryptableBuilder($query)) {
            return parent::{__FUNCTION__}(...func_get_args());
        }
        /** @var BuilderEncrypt $query */
        $encryptableColumns = $query->getEncryptable();

        $value = $this->parameter($where['value']);

        $operator = str_replace('?', '??', $where['operator']);

        return $this->wrap($where['column'], $encryptableColumns) . ' ' . $operator . ' ' . $value;
    }

    /**
     * Compile a "where in" clause.
     *
     * @param \Illuminate\Database\Query\Builder $query
     * @param array $where
     *
     * @return string
     */
    protected function whereIn(Builder $query, $where)
    {
        if (!$this->isEncryptableBuilder($query)) {
            return parent::{__FUNCTION__}(...func_get_args());
        }
        /** @var BuilderEncrypt $query */
        $encryptableColumns = $query->getEncryptable();

        if (!empty($where['values'])) {
            return $this->wrap($where['column'], $encryptableColumns) . ' in (' . $this->parameterize($where['values']) . ')';
        }

        return '0 = 1';
    }

    /**
     * Compile a "where not in" clause.
     *
     * @param \Illuminate\Database\Query\Builder $query
     * @param array $where
     *
     * @return string
     */
    protected function whereNotIn(Builder $query, $where)
    {
        if (!$this->isEncryptableBuilder($query)) {
            return parent::{__FUNCTION__}(...func_get_args());
        }
        /** @var BuilderEncrypt $query */
        $encryptableColumns = $query->getEncryptable();

        if (!empty($where['values'])) {
            return $this->wrap($where['column'], $encryptableColumns) . ' not in (' . $this->parameterize($where['values']) . ')';
        }

        return '1 = 1';
    }

    /**
     * Compile a "where not in raw" clause.
     *
     * For safety, whereIntegerInRaw ensures this method is only used with integer values.
     *
     * @param \Illuminate\Database\Query\Builder $query
     * @param array $where
     *
     * @return string
     */
    protected function whereNotInRaw(Builder $query, $where)
    {
        if (!$this->isEncryptableBuilder($query)) {
            return parent::{__FUNCTION__}(...func_get_args());
        }
        /** @var BuilderEncrypt $query */
        $encryptableColumns = $query->getEncryptable();

        if (!empty($where['values'])) {
            return $this->wrap($where['column'], $encryptableColumns) . ' not in (' . implode(', ', $where['values']) . ')';
        }

        return '1 = 1';
    }

    /**
     * Compile a "where in raw" clause.
     *
     * For safety, whereIntegerInRaw ensures this method is only used with integer values.
     *
     * @param \Illuminate\Database\Query\Builder $query
     * @param array $where
     *
     * @return string
     */
    protected function whereInRaw(Builder $query, $where)
    {
        if (!$this->isEncryptableBuilder($query)) {
            return parent::{__FUNCTION__}(...func_get_args());
        }
        /** @var BuilderEncrypt $query */
        $encryptableColumns = $query->getEncryptable();

        if (!empty($where['values'])) {
            return $this->wrap($where['column'], $encryptableColumns) . ' in (' . implode(', ', $where['values']) . ')';
        }

        return '0 = 1';
    }

    /**
     * Compile a "between" where clause.
     *
     * @param \Illuminate\Database\Query\Builder $query
     * @param array $where
     *
     * @return string
     */
    protected function whereBetween(Builder $query, $where)
    {
        if (!$this->isEncryptableBuilder($query)) {
            return parent::{__FUNCTION__}(...func_get_args());
        }
        /** @var BuilderEncrypt $query */
        $encryptableColumns = $query->getEncryptable();

        $between = $where['not'] ? 'not between' : 'between';

        $min = $this->parameter(is_array($where['values']) ? reset($where['values']) : $where['values'][0]);

        $max = $this->parameter(is_array($where['values']) ? end($where['values']) : $where['values'][1]);

        return $this->wrap($where['column'], $encryptableColumns) . ' ' . $between . ' ' . $min . ' and ' . $max;
    }

    /**
     * Compile a "between" where clause.
     *
     * @param \Illuminate\Database\Query\Builder $query
     * @param array $where
     *
     * @return string
     */
    protected function whereBetweenColumns(Builder $query, $where)
    {
        if (!$this->isEncryptableBuilder($query)) {
            return parent::{__FUNCTION__}(...func_get_args());
        }
        /** @var BuilderEncrypt $query */
        $encryptableColumns = $query->getEncryptable();

        $between = $where['not'] ? 'not between' : 'between';

        $min = $this->wrap((is_array($where['values']) ? reset($where['values']) : $where['values'][0]), $encryptableColumns);

        $max = $this->wrap((is_array($where['values']) ? end($where['values']) : $where['values'][1]), $encryptableColumns);

        return $this->wrap($where['column'], $encryptableColumns) . ' ' . $between . ' ' . $min . ' and ' . $max;
    }

    /**
     * Compile a date based where clause.
     *
     * @param string $type
     * @param \Illuminate\Database\Query\Builder $query
     * @param array $where
     *
     * @return string
     */
    protected function dateBasedWhere($type, Builder $query, $where)
    {
        if (!$this->isEncryptableBuilder($query)) {
            return parent::{__FUNCTION__}(...func_get_args());
        }
        /** @var BuilderEncrypt $query */
        $encryptableColumns = $query->getEncryptable();

        $value = $this->parameter($where['value']);

        return $type . '(' . $this->wrap($where['column'], $encryptableColumns) . ') ' . $where['operator'] . ' ' . $value;
    }

    /**
     * Compile a where clause comparing two columns.
     *
     * @param \Illuminate\Database\Query\Builder $query
     * @param array $where
     *
     * @return string
     */
    protected function whereColumn(Builder $query, $where)
    {
        if (!$this->isEncryptableBuilder($query)) {
            return parent::{__FUNCTION__}(...func_get_args());
        }
        /** @var BuilderEncrypt $query */
        $encryptableColumns = $query->getEncryptable();

        return $this->wrap($where['first'], $encryptableColumns) . ' ' . $where['operator'] . ' ' . $this->wrap($where['second'], $encryptableColumns);
    }

    /**
     * Compile a where row values condition.
     *
     * @param \Illuminate\Database\Query\Builder $query
     * @param array $where
     *
     * @return string
     */
    protected function whereRowValues(Builder $query, $where)
    {
        if (!$this->isEncryptableBuilder($query)) {
            return parent::{__FUNCTION__}(...func_get_args());
        }
        /** @var BuilderEncrypt $query */
        $encryptableColumns = $query->getEncryptable();

        $columns = $this->columnize($where['columns'], $encryptableColumns, false);

        $values = $this->parameterize($where['values']);

        return '(' . $columns . ') ' . $where['operator'] . ' (' . $values . ')';
    }

    /**
     * Compile a "where fulltext" clause.
     *
     * @param \Illuminate\Database\Query\Builder $query
     * @param array $where
     *
     * @return string
     */
    public function whereFullText(Builder $query, $where)
    {
        if (!$this->isEncryptableBuilder($query)) {
            return parent::{__FUNCTION__}(...func_get_args());
        }
        /** @var BuilderEncrypt $query */
        $encryptableColumns = $query->getEncryptable();

        $columns = $this->columnize($where['columns'], $encryptableColumns, false);

        $value = $this->parameter($where['value']);

        $mode = ($where['options']['mode'] ?? []) === 'boolean'
            ? ' in boolean mode'
            : ' in natural language mode';

        $expanded = ($where['options']['expanded'] ?? []) && ($where['options']['mode'] ?? []) !== 'boolean'
            ? ' with query expansion'
            : '';

        return "match ({$columns}) against (" . $value . "{$mode}{$expanded})";
    }

    /**
     * Convert an array of column names into a delimited string.
     *
     * @param array $columns
     * @param array $encryptableColumns
     * @param bool $forceAlias
     *
     * @return string
     */
    public function columnize(array $columns, array $encryptableColumns = [], bool $forceAlias = true)
    {
        $columnizeColumns = [];

        $columns = $this->addColumnsToWildcard($columns, $encryptableColumns);

        foreach ($columns as $column) {
            $wrappedColumn = $this->wrap($column, $encryptableColumns);

            if ($forceAlias
                && $this->isEncryptableColumn($column, $encryptableColumns)
                && str_contains(strtolower($wrappedColumn), ' as ') === false
                && str_contains($wrappedColumn, '*') === false) {
                preg_match_all("/\`.*?\`/", $wrappedColumn, $alias);
                $wrappedColumn = $wrappedColumn . ' as ' . Arr::last($alias[0]);
            }

            $columnizeColumns[] = $wrappedColumn;
        }

        return implode(', ', $columnizeColumns);
    }

    /**
     * if columns only contain a wildcard we add the encrypted columns to decrypt
     *
     * @param array $columns
     * @param array $encryptableColumns
     *
     * @return array
     */
    public function addColumnsToWildcard(array $columns, array $encryptableColumns): array
    {
        //extract the unqualified columns names excluding Expression columns
        $unqualifiedColumns = collect($columns)
            ->filter(fn($column) => is_string($column))
            ->map(fn($column) => $this->toUnqualifiedColumn($column, $encryptableColumns))
            ->toArray();

        $hasWildcard = collect($unqualifiedColumns)
            ->contains(fn ($column) => (is_string($column) && str_contains($column, '*')));

        if ($hasWildcard) {
            $columns = array_merge($columns, array_diff($encryptableColumns, $unqualifiedColumns));
        }

        return $columns;
    }

    /**
     * Create query parameter place-holders for an array.
     *
     * @param array $values
     * @param array $encryptableColumns
     *
     * @return string
     */
    public function parameterize(array $values, array $encryptableColumns = [])
    {
        return (new Collection($values))->map(function ($columnValue, $columnName) use ($encryptableColumns) {
            $parameter = $this->parameter($columnName);
            if (!is_null($columnValue) && !empty($encryptableColumns) && $this->isEncryptableColumn($columnName, $encryptableColumns)) {
                $parameter = EncryptExpressions::encrypt($parameter);
            }
            return $parameter;
        })->implode(', ');
    }

    /**
     * Wrap a value in keyword identifiers.
     *
     * @param Expression|string $value
     * @param array $encryptableColumns
     *
     * @return string
     */
    public function wrap($value, array $encryptableColumns = [])
    {
        if (empty($encryptableColumns)) {
            return parent::wrap($value);
        }

        if ($this->isExpression($value)) {
            return $this->getValue($value);
        }

        // If the value being wrapped has a column alias we will need to separate out
        // the pieces so we can wrap each of the segments of the expression on its
        // own, and then join these both back together using the "as" connector.
        if (stripos($value, ' as ') !== false) {
            return $this->wrapAliasedValue($value, $encryptableColumns);
        }

        // If the given value is a JSON selector we will wrap it differently than a
        // traditional value. We will need to split this path and wrap each part
        // wrapped, etc. Otherwise, we will simply wrap the value as a string.
        /* @todo Need encryption handling */
        if ($this->isJsonSelector($value)) {
            return $this->wrapJsonSelector($value);
        }

        return $this->wrapSegments(explode('.', $value), $encryptableColumns);
    }

    /**
     * Wrap a value that has an alias.
     *
     * @param string $value
     * @param array $encryptableColumns
     *
     * @return string
     */
    protected function wrapAliasedValue($value, array $encryptableColumns = [])
    {
        $segments = preg_split('/\s+as\s+/i', $value);

        return $this->wrap($segments[0], $encryptableColumns) . ' as ' . $this->wrapValue($segments[1]);
    }

    /**
     * Wrap the given value segments.
     *
     * @param $segments
     * @param array $encryptableColumns
     *
     * @return string
     */
    protected function wrapSegments($segments, array $encryptableColumns = [])
    {
        $wrapped = (new Collection($segments))->map(function ($segment, $key) use ($segments) {
            return $key == 0 && count($segments) > 1
                ? $this->wrapTable($segment)
                : $this->wrapValue($segment);
        })->implode('.');

        return $this->isEncryptableColumn(Arr::last($segments), $encryptableColumns)
            ? $this->decryptColumn($wrapped)
            : $wrapped;
    }

    /**
     * @param $value
     * @param array $encryptableColumns
     *
     * @return string
     */
    protected function wrapValue($value, array $encryptableColumns = [])
    {
        if ($value === '*') {
            return $value;
        }
        $wrapped = '`' . str_replace('`', '``', $value) . '`';
        if ($this->isEncryptableColumn($value, $encryptableColumns)) {
            return $this->decryptColumn($wrapped);
        }

        return $wrapped;
    }
}
