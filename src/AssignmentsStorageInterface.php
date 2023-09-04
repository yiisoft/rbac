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
     * @psalm-return array<string, Assignment>
     */
    public function getByUserId(string $userId): array;

    /**
     * Returns all role or permission assignment information by the specified item names' list.
     *
     * @param string[] $itemNames List of item names.
     *
     * @return Assignment[] The assignments. An empty array will be returned if there are no users assigned to these
     * item names.
     * @psalm-return list<Assignment>
     */
    public function getByItemNames(array $itemNames): array;

    /**
     * Returns role or permission assignment for the specified item name that belongs to user with the specified ID.
     *
     * @param string $itemName Item name.
     * @param string $userId The user ID.
     *
     * @return Assignment|null Assignment or null if there is no role or permission assigned to the user.
     */
    public function get(string $itemName, string $userId): ?Assignment;

    /**
     * Whether assignment with a given item name and user id pair exists.
     *
     * @param string $itemName Item name.
     * @param string $userId User id.
     *
     * @return bool Whether assignment exists.
     */
    public function exists(string $itemName, string $userId): bool;

    /**
     * Whether a user has at least one permission from the given list.
     *
     * @param string $userId User id.
     * @param array $permissionNames List of permission names.
     *
     * @return bool Whether a user has at least one permission.
     */
    public function userHasPermission(string $userId, array $permissionNames): bool;

    /**
     * Adds assignment of the role or permission to the user with ID specified.
     *
     * @param string $itemName Item name to assign.
     * @param string $userId The user ID.
     */
    public function add(string $itemName, string $userId): void;

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
    public function removeByUserId(string $userId): void;

    /**
     * Removes all assignments for role or permission.
     *
     * @param string $itemName Name of a role or permission to remove.
     */
    public function removeByItemName(string $itemName): void;

    /**
     * Removes all role and permission assignments.
     */
    public function clear(): void;
}
