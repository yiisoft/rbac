<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

/**
 * `Assignment` represents an assignment of a role or a permission to a user.
 */
final class Assignment
{
    /**
     * @param string $userId The user ID. This should be a string representing the unique identifier of a user.
     * @param string $itemName The role or permission name.
     */
    public function __construct(private string $userId, private string $itemName)
    {
    }

    public function getUserId(): string
    {
        return $this->userId;
    }

    public function getItemName(): string
    {
        return $this->itemName;
    }

    public function withItemName(string $roleName): self
    {
        $new = clone $this;
        $new->itemName = $roleName;
        return $new;
    }
}
