<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Support;

use Yiisoft\Rbac\Assignment;
use Yiisoft\Rbac\AssignmentsStorageInterface;
use Yiisoft\Rbac\Item;

final class FakeAssignmentsStorage implements AssignmentsStorageInterface
{
    private array $assignments = [];
    private int $now;

    public function __construct(int $now)
    {
        $this->now = $now;
    }

    public function getAll(): array
    {
        return $this->assignments;
    }

    public function getUserAssignments(string $userId): array
    {
        return $this->assignments[$userId] ?? [];
    }

    public function get(string $userId, string $name): ?Assignment
    {
        return $this->getUserAssignments($userId)[$name] ?? null;
    }

    public function add(string $userId, string $itemName): void
    {
        $this->assignments[$userId][$itemName] = new Assignment(
            $userId,
            $itemName,
            $this->now
        );
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

    public function remove(string $userId, string $itemName): void
    {
        unset($this->assignments[$userId][$itemName]);
    }

    public function removeUserAssignments(string $userId): void
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

    public function removeItemAssignments(string $itemName): void
    {
        $this->clearAssignmentsFromItemWithName($itemName);
    }

    private function clearAssignmentsFromItemWithName(string $itemName): void
    {
        foreach ($this->assignments as &$assignments) {
            unset($assignments[$item]);
        }
    }
}
