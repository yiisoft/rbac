<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

/**
 * `AssignmentsStorageInterface` represents a storage for assignment of RBAC items (a role or a permission) to a user
 * used in {@see Manager}.
 */
interface AssignmentsStorageInterface
{
    /**
     * Returns all role and permission assignment information.
     *
     * @return array
     * @psalm-return array<string,array<string, Assignment>>
     */
    public function getAll(): array;

    /**
     * Returns all role or permission assignment information for the specified user.
     *
     * @param string $userId The user ID.
     *
     * @return Assignment[] The assignments. The array is indexed by the role or the permission names. An empty array
     * will be returned if there is no role or permission assigned to the user.
     *
     * @psalm-return array<string, Assignment>
     */
    public function getAllByUser(string $userId): array;

    /**
     * Returns role or permission assignment for the specified item name that belongs to user with the specified ID.
     *
     * @param string $userId The user ID.
     * @param string $name Role name.
     *
     * @return Assignment|null Assignment or null if there is no role or permission assigned to the user.
     */
    public function get(string $userId, string $name): ?Assignment;

    /**
     * Adds assignment of the role or permission to the user with ID specified.
     *
     * @param string $userId The user ID.
     * @param string $itemName Item name to assign.
     */
    public function add(string $userId, string $itemName): void;

    /**
     * Returns whether there is assignment for a named role or permission.
     *
     * @param string $name Name of the role or the permission.
     *
     * @return bool Whether there is assignment.
     */
    public function hasItem(string $name): bool;

    /**
     * Change name of an item in assignments.
     *
     * @param string $oldName Old name of the role or the permission.
     * @param string $newName New name of the role or permission.
     */
    public function renameItem(string $oldName, string $newName): void;

    /**
     * Removes assignment of a role or a permission to the user with ID specified.
     *
     * @param string $itemName Name of a role or permission to remove assignment from.
     * @param string $userId The user ID.
     */
    public function remove(string $itemName, string $userId): void;

    /**
     * Removes all role or permission assignments for a user with ID specified.
     *
     * @param string $userId The user ID.
     */
    public function removeAllByUserId(string $userId): void;

    /**
     * Removes all assignments for role or permission.
     *
     * @param string $itemName Name of a role or permission to remove.
     */
    public function removeAllByItemName(string $itemName): void;

    /**
     * Removes all role and permission assignments.
     */
    public function clear(): void;
}
