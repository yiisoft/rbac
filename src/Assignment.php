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
     * @param int $createdAt UNIX timestamp representing the assignment creation time.
     */
    public function __construct(private string $userId, private string $itemName, private int $createdAt)
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

    public function getCreatedAt(): int
    {
        return $this->createdAt;
    }

    /**
     * @return array Attribute values indexed by corresponding names.
     * @psalm-return array{
     *     item_name: string,
     *     user_id: string,
     *     created_at: int
     * }
     */
    final public function getAttributes(): array
    {
        return [
            'item_name' => $this->getItemName(),
            'user_id' => $this->getUserId(),
            'created_at' => $this->getCreatedAt(),
        ];
    }
}
