<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

trait SchemaManagerTrait
{
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
}
