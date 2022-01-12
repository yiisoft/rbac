<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

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

    public function getAssignments(): array
    {
        return $this->assignments;
    }

    public function getUserAssignments(string $userId): array
    {
        return $this->assignments[$userId] ?? [];
    }

    public function getUserAssignmentByName(string $userId, string $name): ?Assignment
    {
        return $this->getUserAssignments($userId)[$name] ?? null;
    }

    public function addAssignment(string $userId, Item $item): void
    {
        $this->assignments[$userId][$item->getName()] = new Assignment(
            $userId,
            $item->getName(),
            $this->now
        );
    }

    public function assignmentExist(string $name): bool
    {
        foreach ($this->getAssignments() as $assignmentInfo) {
            foreach ($assignmentInfo as $itemName => $assignment) {
                if ($itemName === $name) {
                    return true;
                }
            }
        }
        return false;
    }

    public function removeAssignment(string $userId, Item $item): void
    {
        unset($this->assignments[$userId][$item->getName()]);
    }

    public function removeAllAssignments(string $userId): void
    {
        $this->assignments[$userId] = [];
    }

    public function clearAssignments(): void
    {
        $this->assignments = [];
    }

    public function updateAssignmentsForItemName(string $name, Item $item): void
    {
        foreach ($this->assignments as &$assignments) {
            if (isset($assignments[$name])) {
                $assignments[$item->getName()] = $assignments[$name]->withItemName($item->getName());
                unset($assignments[$name]);
            }
        }
    }

    public function removeAssignmentsFromItem(Item $item): void
    {
        $this->clearAssignmentsFromItem($item);
    }

    private function clearAssignmentsFromItem(Item $item): void
    {
        foreach ($this->assignments as &$assignments) {
            unset($assignments[$item->getName()]);
        }
    }
}
