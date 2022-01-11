<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

/**
 * StorageInterface represents a storage for RBAC items used in {@see Manager}.
 */
interface AssignmentsStorageInterface
{
    /**
     * Returns all role assignment information.
     *
     * @psalm-return array<string,array<string, Assignment>>
     *
     * @return array
     */
    public function getAssignments(): array;

    /**
     * Returns all role assignment information for the specified user.
     *
     * @param string $userId The user ID.
     *
     * @return Assignment[] The assignments. An empty array will be
     * returned if there is no role assigned to the user.
     */
    public function getUserAssignments(string $userId): array;

    /**
     * Returns role assignment for the specified item name that belongs to user with the specified ID.
     *
     * @param string $userId The user ID.
     * @param string $name Role name.
     *
     * @return Assignment|null Assignment or null if there is no role assigned to the user.
     */
    public function getUserAssignmentByName(string $userId, string $name): ?Assignment;

    /**
     * Adds assignment of the role to the user with ID specified.
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
     * Updates assignments for the specified role, permission or rule in the system.
     *
     * @param string $name
     * @param Item $item
     */
    public function updateAssignmentsForItemName(string $name, Item $item): void;

    /**
     * Removes assignment of a role to the user with ID specified.
     *
     * @param string $userId The user ID.
     * @param Item $item Role to remove assignment to.
     */
    public function removeAssignment(string $userId, Item $item): void;

    /**
     * Removes all role assignments for a user with ID specified.
     *
     * @param string $userId The user ID.
     */
    public function removeAllAssignments(string $userId): void;

    /**
     * Removes a assignments for role, permission or rule.
     *
     * @param Item $item Item to remove.
     */
    public function removeAssignmentsFromItem(Item $item): void;

    /**
     * Removes all role assignments.
     */
    public function clearAssignments(): void;
}
