<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

use Closure;
use Exception;
use InvalidArgumentException;
use RuntimeException;
use Stringable;
use Yiisoft\Access\AccessCheckerInterface;
use Yiisoft\Rbac\Exception\DefaultRolesNotFoundException;
use Yiisoft\Rbac\Exception\ItemAlreadyExistsException;

/**
 * An interface for managing RBAC entities (items, assignments, rules) with possibility to check user permissions.
 *
 * @psalm-import-type ItemsIndexedByName from ItemsStorageInterface
 */
interface ManagerInterface extends AccessCheckerInterface
{
    /**
     * Checks the possibility of adding a child to a parent.
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
     * Returns whether named parent has children.
     *
     * @param string $parentName The parent name.
     *
     * @return bool Whether named parent has children.
     */
    public function hasChildren(string $parentName): bool;

    /**
     * Assigns a role or permission to a user.
     *
     * @param string $itemName Name of the role or the permission to be assigned.
     * @param int|string|Stringable $userId The user ID.
     * @param int|null $createdAt UNIX timestamp representing assignment creation time. When `null`, current time is
     * used.
     *
     * @throws Exception If the role or permission has already been assigned to the user.
     *
     * @return self
     */
    public function assign(string $itemName, int|Stringable|string $userId, ?int $createdAt = null): self;

    /**
     * Revokes a role or a permission from a user.
     *
     * @param string $itemName The name of the role or permission to be revoked.
     * @param int|string|Stringable $userId The user ID.
     *
     * @return self
     */
    public function revoke(string $itemName, int|Stringable|string $userId): self;

    /**
     * Revokes all roles and permissions from a user.
     *
     * @param int|string|Stringable $userId The user ID.
     *
     * @return self
     */
    public function revokeAll(int|Stringable|string $userId): self;

    /**
     * Returns the items that are assigned to the user via {@see assign()}.
     *
     * @param int|string|Stringable $userId The user ID.
     *
     * @return array All items directly assigned to the user. The array is indexed by the item names.
     * @psalm-return ItemsIndexedByName
     */
    public function getItemsByUserId(int|Stringable|string $userId): array;

    /**
     * Returns the roles that are assigned to the user via {@see assign()}.
     *
     * @param int|string|Stringable $userId The user ID.
     *
     * @return Role[] All roles directly assigned to the user. The array is indexed by the role names.
     * @psalm-return array<string, Role>
     */
    public function getRolesByUserId(int|Stringable|string $userId): array;

    /**
     * Returns child roles of the role specified. Depth isn't limited.
     *
     * @param string $roleName Name of the role to get child roles for.
     *
     * @throws InvalidArgumentException If the role was not found by `$roleName`.
     *
     * @return Role[] Child roles. The array is indexed by the role names.
     * @psalm-return array<string, Role>
     */
    public function getChildRoles(string $roleName): array;

    /**
     * Returns all permissions that the specified role represents.
     *
     * @param string $roleName The role name.
     *
     * @return Permission[] All permissions that the role represents. The array is indexed by the permission names.
     * @psalm-return array<string, Permission>
     */
    public function getPermissionsByRoleName(string $roleName): array;

    /**
     * Returns all permissions that the user has.
     *
     * @param int|string|Stringable $userId The user ID.
     *
     * @return Permission[] All permissions that the user has. The array is indexed by the permission names.
     * @psalm-return array<string, Permission>
     */
    public function getPermissionsByUserId(int|Stringable|string $userId): array;

    /**
     * Returns all user IDs assigned to the role specified.
     *
     * @param string $roleName The role name.
     *
     * @return array Array of user ID strings.
     */
    public function getUserIdsByRoleName(string $roleName): array;

    /**
     * @throws ItemAlreadyExistsException
     */
    public function addRole(Role $role): self;

    /**
     * @param string $name The role name.
     */
    public function getRole(string $name): ?Role;

    /**
     * @param string $name The role name.
     * @param Role $role Role instance with updated data.
     */
    public function updateRole(string $name, Role $role): self;

    /**
     * @param string $name The role name.
     */
    public function removeRole(string $name): self;

    /**
     * @throws ItemAlreadyExistsException
     */
    public function addPermission(Permission $permission): self;

    /**
     * @param string $name The permission name.
     */
    public function getPermission(string $name): ?Permission;

    /**
     * @param string $name The permission name.
     */
    public function removePermission(string $name): self;

    /**
     * @param string $name The permission name.
     * @param Permission $permission Permission instance with updated data.
     */
    public function updatePermission(string $name, Permission $permission): self;

    /**
     * Set default role names.
     *
     * @param array|Closure $roleNames Either array of role names or a closure returning it.
     *
     * @throws InvalidArgumentException When role names is not a list of strings passed directly or resolved from a
     * closure.
     */
    public function setDefaultRoleNames(array|Closure $roleNames): self;

    /**
     * Returns default role names.
     *
     * @return string[] Default role names.
     */
    public function getDefaultRoleNames(): array;

    /**
     * Returns default roles.
     *
     * @throws DefaultRolesNotFoundException When at least 1 of the default roles was not found.
     * @return Role[] Default roles. The array is indexed by the role names.
     * @psalm-return array<string, Role>
     */
    public function getDefaultRoles(): array;

    /**
     * Set guest role name.
     *
     * @param string|null $name The guest role name.
     */
    public function setGuestRoleName(?string $name): self;

    /**
     * Get guest role name.
     *
     * @return string|null The guest role name or `null` if it was not set.
     */
    public function getGuestRoleName(): ?string;

    /**
     * Get a guest role.
     *
     * @throws InvalidArgumentException When a role was not found.
     * @return Role|null Guest role or `null` if the name was not set.
     */
    public function getGuestRole(): ?Role;
}
