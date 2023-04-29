<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

use InvalidArgumentException;

trait SchemaManagerTrait
{
    /**
     * @var string A name of the table for storing RBAC items (roles and permissions).
     * @psalm-var non-empty-string
     */
    private string $itemsTable;
    /**
     * @var string A name of the table for storing RBAC assignments.
     * @psalm-var non-empty-string
     */
    private string $assignmentsTable;
    /**
     * @var string A name of the table for storing relations between RBAC items.
     * @psalm-var non-empty-string
     */
    private string $itemsChildrenTable;

    public function createAll(bool $force = true): void
    {
        if ($force === true) {
            $this->dropAll();
        }

        $this->createItemsTable();
        $this->createItemsChildrenTable();
        $this->createAssignmentsTable();
    }

    public function dropAll(): void
    {
        $this->dropTable($this->itemsChildrenTable);
        $this->dropTable($this->assignmentsTable);
        $this->dropTable($this->itemsTable);
    }

    public function getItemsTable(): string
    {
        return $this->itemsTable;
    }

    public function getAssignmentsTable(): string
    {
        return $this->assignmentsTable;
    }

    public function getItemsChildrenTable(): string
    {
        return $this->itemsChildrenTable;
    }

    private function initTables(string $itemsTable, string $assignmentsTable, $itemsChildrenTable): void
    {
        if ($itemsTable === '') {
            throw new InvalidArgumentException('Items table name can\'t be empty.');
        }

        $this->itemsTable = $itemsTable;

        if ($assignmentsTable === '') {
            throw new InvalidArgumentException('Assignments table name can\'t be empty.');
        }

        $this->assignmentsTable = $assignmentsTable;

        if ($itemsChildrenTable === '') {
            throw new InvalidArgumentException('Items children table name can\'t be empty.');
        }

        $this->itemsChildrenTable = $itemsChildrenTable ?? $this->itemsTable . '_child';
    }
}
