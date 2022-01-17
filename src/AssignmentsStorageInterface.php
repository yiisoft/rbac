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
     * Returns all role or permission assignment information.
     *
     * @return array
     * @psalm-return array<string,array<string, Assignment>>
     */
    public function getAssignments(): array;

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
    public function getUserAssignments(string $userId): array;

    /**
     * Returns role or permission assignment for the specified item name that belongs to user with the specified ID.
     *
     * @param string $userId The user ID.
     * @param string $name Role name.
     *
     * @return Assignment|null Assignment or null if there is no role or permission assigned to the user.
     */
    public function getUserAssignmentByName(string $userId, string $name): ?Assignment;

    /**
     * Adds assignment of the role or permission to the user with ID specified.
     *
     * @param string $userId The user ID.
     * @param Item $item Role to assign.
     */
    public function addAssignment(string $userId, Item $item): void;

    /**
     * Returns whether there is assignment for a named role or permission.
     *
     * @param string $name Name of the role or the permission.
     *
     * @return bool Whether there is assignment.
     */
    public function assignmentExist(string $name): bool;

    /**
     * Updates assignments for the specified role or permission.
     *
     * @param string $name Name of the role or the permission.
     * @param Item $item Role or permission.
     */
    public function updateAssignmentsForItemName(string $name, Item $item): void;

    /**
     * Removes assignment of a role or a permission to the user with ID specified.
     *
     * @param string $userId The user ID.
     * @param Item $item Role or permission to remove assignment from.
     */
    public function removeAssignment(string $userId, Item $item): void;

    /**
     * Removes all role or permission assignments for a user with ID specified.
     *
     * @param string $userId The user ID.
     */
    public function removeAllAssignments(string $userId): void;

    /**
     * Removes all assignments for role or permission.
     *
     * @param Item $item Role or permission to remove.
     */
    public function removeAssignmentsFromItem(Item $item): void;

    /**
     * Removes all role and permission assignments.
     */
    public function clearAssignments(): void;
}
