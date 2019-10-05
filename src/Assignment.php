<?php
namespace Yiisoft\Rbac;

/**
 * Assignment represents an assignment of a role or a permission to a user.
 */
class Assignment
{
    /**
     * @var string the user ID. This should be a string representing the unique identifier of a user.
     */
    private $userId;
    /**
     * @var string the role or permission name
     */
    private $itemName;

    /**
     * @var int UNIX timestamp representing the assignment creation time.
     */
    private $createdAt;

    /**
     * @param string $userId the user ID. This should be a string representing the unique identifier of a user.
     * @param string $itemName the role or permission name.
     * @param int $createdAt UNIX timestamp representing the assignment creation time.
     */
    public function __construct(string $userId, string $itemName, int $createdAt)
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

    public function getCreatedAt(): ?int
    {
        return $this->createdAt;
    }
}
