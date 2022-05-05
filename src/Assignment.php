<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

use DateTime;

/**
 * `Assignment` represents an assignment of a role or a permission to a user.
 */
final class Assignment
{
    /**
     * @var string The user ID. This should be a string representing the unique identifier of a user.
     */
    private string $userId;

    /**
     * @var string The role or permission name.
     */
    private string $itemName;

    /**
     * @var DateTime UNIX timestamp representing the assignment creation time.
     */
    private DateTime $createdAt;

    /**
     * @param string $userId The user ID. This should be a string representing the unique identifier of a user.
     * @param string $itemName The role or permission name.
     * @param DateTime $createdAt UNIX timestamp representing the assignment creation time.
     */
    public function __construct(string $userId, string $itemName, DateTime $createdAt)
    {
        $this->userId = $userId;
        $this->itemName = $itemName;
        $this->createdAt = $createdAt;
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

    public function getCreatedAt(): DateTime
    {
        return $this->createdAt;
    }
}
