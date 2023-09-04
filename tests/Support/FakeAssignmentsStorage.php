<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Support;

use Yiisoft\Rbac\Assignment;
use Yiisoft\Rbac\AssignmentsStorageInterface;

class FakeAssignmentsStorage implements AssignmentsStorageInterface
{
    private array $assignments = [];

    public function getAll(): array
    {
        return $this->assignments;
    }

    public function getByUserId(string $userId): array
    {
        return $this->assignments[$userId] ?? [];
    }

    public function getByItemNames(array $itemNames): array
    {
        $result = [];

        foreach ($this->assignments as $assignments) {
            foreach ($assignments as $userAssignment) {
                if (in_array($userAssignment->getItemName(), $itemNames, true)) {
                    $result[] = $userAssignment;
                }
            }
        }

        return $result;
    }

    public function get(string $itemName, string $userId): ?Assignment
    {
        return $this->getByUserId($userId)[$itemName] ?? null;
    }

    public function userHasPermission(string $userId, array $permissionNames): bool
    {
        $assignments = $this->getByUserId($userId);
        if (empty($assignments)) {
            return false;
        }

        foreach ($permissionNames as $permissionName) {
            if (array_key_exists($permissionName, $assignments)) {
                return true;
            }
        }

        return false;
    }

    public function add(string $itemName, string $userId): void
    {
        $this->assignments[$userId][$itemName] = new Assignment($userId, $itemName, time());
    }

    public function hasItem(string $name): bool
    {
        foreach ($this->getAll() as $assignmentInfo) {
            foreach ($assignmentInfo as $itemName => $assignment) {
                if ($itemName === $name) {
                    return true;
                }
            }
        }
        return false;
    }

    public function remove(string $itemName, string $userId): void
    {
        unset($this->assignments[$userId][$itemName]);
    }

    public function removeByUserId(string $userId): void
    {
        $this->assignments[$userId] = [];
    }

    public function clear(): void
    {
        $this->assignments = [];
    }

    public function renameItem(string $oldName, string $newName): void
    {
        foreach ($this->assignments as &$assignments) {
            if (isset($assignments[$oldName])) {
                $assignments[$newName] = $assignments[$oldName]->withItemName($newName);
                unset($assignments[$oldName]);
            }
        }
    }

    public function removeByItemName(string $itemName): void
    {
        $this->clearAssignmentsFromItemWithName($itemName);
    }

    private function clearAssignmentsFromItemWithName(string $itemName): void
    {
        foreach ($this->assignments as &$assignments) {
            unset($assignments[$itemName]);
        }
    }
}
