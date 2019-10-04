<?php
namespace Yiisoft\Rbac;

/**
 * Assignment represents an assignment of a role to a user.
 */
class Assignment
{
    /**
     * @var string the user ID. This should be a string representing the unique identifier of a user.
     */
    private $userId;
    /**
     * @var string the role name
     */
    private $roleName;

    /**
     * @var int UNIX timestamp representing the assignment creation time.
     */
    private $createdAt;

    /**
     * @param string $userId the user ID. This should be a string representing the unique identifier of a user.
     * @param string $roleName the role name.
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

    public function getCreatedAt(): ?int
    {
        return $this->createdAt;
    }
}
