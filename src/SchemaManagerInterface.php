<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

interface SchemaManagerInterface
{
    public function createItemsTable(): void;

    public function createItemsChildrenTable(): void;

    public function createAssignmentsTable(): void;

    public function hasTable(string $tableName): bool;

    public function dropTable(string $tableName): void;

    public function createAll(): void;

    public function dropAll(): void;
}
