<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

/**
 * A storage for RBAC roles and permissions used in {@see Manager}.
 *
 * @psalm-type ItemsIndexedByName = array<string, Item>
 */
interface ItemsStorageInterface
{
    /**
     * Removes all roles and permissions.
     */
    public function clear(): void;

    /**
     * Returns all roles and permissions in the system.
     *
     * @return Item[] All roles and permissions in the system.
     */
    public function getAll(): array;

    /**
     * Returns the named role or permission.
     *
     * @param string $name The role or the permission name.
     *
     * @return Permission|Role|null The role or the permission corresponding to the specified name. `null` is returned if no such
     * item.
     */
    public function get(string $name): Permission|Role|null;

    /**
     * Whether named role or permission exists.
     *
     * @param string $name The role or the permission name.
     *
     * @return bool Whether named role or permission exists.
     */
    public function exists(string $name): bool;

    /**
     * Whether named role exists.
     *
     * @param string $name The role name.
     *
     * @return bool Whether named role exists.
     */
    public function roleExists(string $name): bool;

    /**
     * Adds the role or the permission to RBAC system.
     *
     * @param Permission|Role $item The role or the permission to add.
     */
    public function add(Permission|Role $item): void;

    /**
     * Updates the specified role or permission in the system.
     *
     * @param string $name The old name of the role or permission.
     * @param Permission|Role $item Modified role or permission.
     */
    public function update(string $name, Permission|Role $item): void;

    /**
     * Removes a role or permission from the RBAC system.
     *
     * @param string $name Name of a role or a permission to remove.
     */
    public function remove(string $name): void;

    /**
     * Returns all roles in the system.
     *
     * @return Role[] Array of role instances indexed by role names.
     * @psalm-return array<string, Role>
     */
    public function getRoles(): array;

    /**
     * Returns roles by the given names' list.
     *
     * @param string[] $names List of role names.
     *
     * @return Role[] Array of role instances indexed by role names.
     * @psalm-return array<string, Role>
     */
    public function getRolesByNames(array $names): array;

    /**
     * Returns the named role.
     *
     * @param string $name The role name.
     *
     * @return Role|null The role corresponding to the specified name. `null` is returned if no such role.
     */
    public function getRole(string $name): ?Role;

    /**
     * Removes all roles.
     * All parent child relations will be adjusted accordingly.
     */
    public function clearRoles(): void;

    /**
     * Returns all permissions in the system.
     *
     * @return Permission[] Array of permission instances indexed by permission names.
     * @psalm-return array<string, Permission>
     */
    public function getPermissions(): array;

    /**
     * Returns permissions by the given names' list.
     *
     * @param string[] $names List of permission names.
     *
     * @return Permission[] Array of permission instances indexed by permission names.
     * @psalm-return array<string, Permission>
     */
    public function getPermissionsByNames(array $names): array;

    /**
     * Returns the named permission.
     *
     * @param string $name The permission name.
     *
     * @return Permission|null The permission corresponding to the specified name. `null` is returned if there is no
     * such permission.
     */
    public function getPermission(string $name): ?Permission;

    /**
     * Removes all permissions.
     * All parent child relations will be adjusted accordingly.
     */
    public function clearPermissions(): void;

    /**
     * Returns the parent permissions and/or roles.
     *
     * @param string $name The child name.
     *
     * @return Item[] The parent permissions and/or roles.
     *
     * @psalm-return ItemsIndexedByName
     */
    public function getParents(string $name): array;

    /**
     * Returns direct child permissions and/or roles.
     *
     * @param string $name The parent name.
     *
     * @return Item[] The child permissions and/or roles.
     *
     * @psalm-return ItemsIndexedByName
     */
    public function getDirectChildren(string $name): array;

    /**
     * Returns all child permissions and/or roles.
     *
     * @param string $name The parent name.
     *
     * @return Item[] The child permissions and/or roles.
     * @psalm-return array<string, Item>
     */
    public function getAllChildren(string $name): array;

    /**
     * Returns all child roles.
     *
     * @param string $name The parent name.
     *
     * @return Role[] The child roles.
     * @psalm-return array<string, Role>
     */
    public function getAllChildRoles(string $name): array;

    /**
     * Returns all child permissions.
     *
     * @param string $name The parent name.
     *
     * @return Permission[] The child permissions.
     * @psalm-return array<string, Permission>
     */
    public function getAllChildPermissions(string $name): array;

    /**
     * Returns whether named parent has children.
     *
     * @param string $name The parent name.
     *
     * @return bool Whether named parent has children.
     */
    public function hasChildren(string $name): bool;

    /**
     * Returns whether selected parent has a child with a given name.
     *
     * @param string $parentName The parent name.
     * @param string $childName The child name.
     *
     * @return bool Whether selected parent has a child with a given name.
     */
    public function hasChild(string $parentName, string $childName): bool;

    /**
     * Returns whether selected parent has a direct child with a given name.
     *
     * @param string $parentName The parent name.
     * @param string $childName The child name.
     *
     * @return bool Whether selected parent has a direct child with a given name.
     */
    public function hasDirectChild(string $parentName, string $childName): bool;

    /**
     * Adds a role or a permission as a child of another role or permission.
     *
     * @param string $parentName Name of the parent to add child to.
     * @param string $childName Name of the child to add.
     */
    public function addChild(string $parentName, string $childName): void;

    /**
     * Removes a child from its parent.
     * Note, the child role or permission is not deleted. Only the parent-child relationship is removed.
     *
     * @param string $parentName Name of the parent to remove child from.
     * @param string $childName Name of the child to remove.
     */
    public function removeChild(string $parentName, string $childName): void;

    /**
     * Removed all children form their parent.
     * Note, the children roles or permissions are not deleted. Only the parent-child relationships are removed.
     *
     * @param string $parentName Name of the parent to remove children from.
     */
    public function removeChildren(string $parentName): void;
}
