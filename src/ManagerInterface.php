<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

use Closure;
use Exception;
use InvalidArgumentException;
use RuntimeException;
use Yiisoft\Access\AccessCheckerInterface;
use Yiisoft\Rbac\Exception\ItemAlreadyExistsException;

/**
 * An interface for managing RBAC entities (items, assignments, rules) with possibility to check user permissions.
 */
interface ManagerInterface extends AccessCheckerInterface
{
    /**
     * Checks the possibility of adding a child to parent.
     *
     * @param string $parentName The name of the parent item.
     * @param string $childName The name of the child item to be added to the hierarchy.
     *
     * @return bool Whether it is possible to add the child to the parent.
     */
    public function canAddChild(string $parentName, string $childName): bool;

    /**
     * Adds an item as a child of another item.
     *
     * @param string $parentName The name of the parent item.
     * @param string $childName The name of the child item.
     *
     * @throws RuntimeException
     * @throws InvalidArgumentException
     *
     * @return self
     */
    public function addChild(string $parentName, string $childName): self;

    /**
     * Removes a child from its parent.
     * Note, the child item is not deleted. Only the parent-child relationship is removed.
     *
     * @param string $parentName The name of the parent item.
     * @param string $childName The name of the child item.
     *
     * @return self
     */
    public function removeChild(string $parentName, string $childName): self;

    /**
     * Removes all children form their parent.
     * Note, the children items are not deleted. Only the parent-child relationships are removed.
     *
     * @param string $parentName The name of the parent item.
     *
     * @return self
     */
    public function removeChildren(string $parentName): self;

    /**
     * Returns a value indicating whether the child already exists for the parent.
     *
     * @param string $parentName The name of the parent item.
     * @param string $childName The name of the child item.
     *
     * @return bool Whether `$child` is already a child of `$parent`
     */
    public function hasChild(string $parentName, string $childName): bool;

    /**
     * Assigns a role or permission to a user.
     *
     * @param string $itemName Name of the role or the permission to be assigned.
     * @param int|object|string $userId The user ID.
     *
     * @throws Exception If the role or permission has already been assigned to the user.
     *
     * @return self
     */
    public function assign(string $itemName, int|Stringable|string $userId): self;

    /**
     * Revokes a role or a permission from a user.
     *
     * @param string $itemName The name of the role or permission to be revoked.
     * @param int|object|string $userId The user ID.
     *
     * @return self
     */
    public function revoke(string $itemName, int|object|string $userId): self;

    /**
     * Revokes all roles and permissions from a user.
     *
     * @param int|object|string $userId The user ID.
     *
     * @return self
     */
    public function revokeAll(int|object|string $userId): self;

    /**
     * Returns the roles that are assigned to the user via {@see assign()}.
     * Note that child roles that are not assigned directly to the user will not be returned.
     *
     * @param int|object|string $userId The user ID.
     *
     * @return Role[] All roles directly assigned to the user. The array is indexed by the role names.
     */
    public function getRolesByUserId(int|object|string $userId): array;

    /**
     * Returns child roles of the role specified. Depth isn't limited.
     *
     * @param string $roleName Name of the role to get child roles for.
     *
     * @throws InvalidArgumentException If role was not found by `$roleName`.
     *
     * @return Role[] Child roles. The array is indexed by the role names. First element is an instance of the parent
     * role itself.
     */
    public function getChildRoles(string $roleName): array;

    /**
     * Returns all permissions that the specified role represents.
     *
     * @param string $roleName The role name.
     *
     * @return Permission[] All permissions that the role represents. The array is indexed by the permission names.
     * @psalm-return array<string,Permission>
     */
    public function getPermissionsByRoleName(string $roleName): array;

    /**
     * Returns all permissions that the user has.
     *
     * @param int|object|string $userId The user ID.
     *
     * @return Permission[] All permissions that the user has. The array is indexed by the permission names.
     */
    public function getPermissionsByUserId(int|object|string $userId): array;

    /**
     * Returns all user IDs assigned to the role specified.
     *
     * @param string $roleName The role name.
     *
     * @return array Array of user ID strings.
     */
    public function getUserIdsByRoleName(string $roleName): array;

    /**
     * @param Role $role
     *
     * @throws ItemAlreadyExistsException
     *
     * @return self
     */
    public function addRole(Role $role): self;

    /**
     * @param string $name The role name.
     *
     * @return self
     */
    public function removeRole(string $name): self;

    /**
     * @param string $name The role name.
     * @param Role $role
     *
     * @return self
     */
    public function updateRole(string $name, Role $role): self;

    /**
     * @param Permission $permission
     *
     * @throws ItemAlreadyExistsException
     *
     * @return self
     */
    public function addPermission(Permission $permission): self;

    /**
     * @param string $permissionName The permission name.
     *
     * @return self
     */
    public function removePermission(string $permissionName): self;

    /**
     * @param string $name The permission name.
     * @param Permission $permission
     *
     * @return self
     */
    public function updatePermission(string $name, Permission $permission): self;

    /**
     * Set default role names.
     *
     * @param Closure|string[] $roleNames Either array of role names or a closure returning it.
     *
     * @throws InvalidArgumentException When `$roles` is neither array nor closure.
     * @throws RuntimeException When callable returns not array.
     */
    public function setDefaultRoleNames(Closure|array $roleNames): self;

    /**
     * Returns default role names.
     *
     * @return string[] Default role names.
     */
    public function getDefaultRoleNames(): array;

    /**
     * Returns default roles.
     *
     * @return Role[] Default roles. The array is indexed by the role names.
     */
    public function getDefaultRoles(): array;

    /**
     * Set guest role name.
     *
     * @param string|null $name The guest role name.
     */
    public function setGuestRoleName(?string $name): self;
}
