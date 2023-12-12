<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

use function array_key_exists;

abstract class SimpleAssignmentsStorage implements AssignmentsStorageInterface
{
    /**
     * @psalm-var array<string, array<string, Assignment>>
     */
    protected array $assignments = [];

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

    public function exists(string $itemName, string $userId): bool
    {
        return isset($this->getByUserId($userId)[$itemName]);
    }

    public function userHasItem(string $userId, array $itemNames): bool
    {
        $assignments = $this->getByUserId($userId);
        if (empty($assignments)) {
            return false;
        }

        foreach ($itemNames as $itemName) {
            if (array_key_exists($itemName, $assignments)) {
                return true;
            }
        }

        return false;
    }

    public function filterUserItemNames(string $userId, array $itemNames): array
    {
        $assignments = $this->getByUserId($userId);
        if (empty($assignments)) {
            return [];
        }

        $userItemNames = [];
        foreach ($itemNames as $itemName) {
            if (array_key_exists($itemName, $assignments)) {
                $userItemNames[] = $itemName;
            }
        }

        return $userItemNames;
    }

    public function add(Assignment $assignment): void
    {
        $this->assignments[$assignment->getUserId()][$assignment->getItemName()] = $assignment;
    }

    public function hasItem(string $name): bool
    {
        foreach ($this->getAll() as $assignmentInfo) {
            if (array_key_exists($name, $assignmentInfo)) {
                return true;
            }
        }

        return false;
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

    public function remove(string $itemName, string $userId): void
    {
        unset($this->assignments[$userId][$itemName]);
    }

    public function removeByUserId(string $userId): void
    {
        $this->assignments[$userId] = [];
    }

    public function removeByItemName(string $itemName): void
    {
        foreach ($this->assignments as &$assignments) {
            unset($assignments[$itemName]);
        }
    }

    public function clear(): void
    {
        $this->assignments = [];
    }
}
