<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

/**
 * `Assignment` represents an assignment of a role to a user.
 */
final class Assignment
{
    /**
     * @var string The user ID. This should be a string representing the unique identifier of a user.
     */
    private string $userId;

    /**
     * @var string The role name.
     */
    private string $roleName;

    /**
     * @var int UNIX timestamp representing the assignment creation time.
     */
    private int $createdAt;

    /**
     * @param string $userId The user ID. This should be a string representing the unique identifier of a user.
     * @param string $roleName The role name.
     * @param int $createdAt UNIX timestamp representing the assignment creation time.
     */
    public function __construct(string $userId, string $roleName, int $createdAt)
    {
        $this->userId = $userId;
        $this->roleName = $roleName;
        $this->createdAt = $createdAt;
    }

    public function getUserId(): string
    {
        return $this->userId;
    }

    public function getRoleName(): string
    {
        return $this->roleName;
    }

    public function withRoleName(string $roleName): self
    {
        $new = clone $this;
        $new->roleName = $roleName;
        return $new;
    }

    public function getCreatedAt(): int
    {
        return $this->createdAt;
    }
}
