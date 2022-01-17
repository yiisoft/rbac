<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

/**
 * `RolesStorageInterface` represents a storage for RBAC items used in {@see Manager}.
 */
interface RolesStorageInterface
{
    /**
     * Removes all authorization data, including roles, permissions, and rules.
     */
    public function clear(): void;

    /**
     * Returns all roles and permissions in the system.
     *
     * @return Item[] All roles and permissions in the system.
     */
    public function getItems(): array;

    /**
     * Returns the named role or permission.
     *
     * @param string $name The role or the permission name.
     *
     * @return Item|null The role or the permission corresponding to the specified name. `null` is returned if no such
     * item.
     */
    public function getItemByName(string $name): ?Item;

    /**
     * Adds the role or the permission to RBAC system.
     *
     * @param Item $item The role or the permission to add.
     */
    public function addItem(Item $item): void;

    /**
     * Updates the specified role or permission in the system.
     *
     * @param string $name The old name of the role or permission.
     * @param Item $item Modified role or permission.
     */
    public function updateItem(string $name, Item $item): void;

    /**
     * Removes a role or permission from the RBAC system.
     *
     * @param Item $item Role or permission to remove.
     */
    public function removeItem(Item $item): void;

    /**
     * @return array
     * @psalm-return array<string,Item[]>
     */
    public function getChildren(): array;

    /**
     * Returns all roles in the system.
     *
     * @return Role[] All roles in the system.
     */
    public function getRoles(): array;

    /**
     * Returns the named role.
     *
     * @param string $name The role name.
     *
     * @return Role|null The role corresponding to the specified name. `null` is returned if no such role.
     */
    public function getRoleByName(string $name): ?Role;

    /**
     * Removes all roles.
     * All parent child relations will be adjusted accordingly.
     */
    public function clearRoles(): void;

    /**
     * Returns all permissions in the system.
     *
     * @return Permission[] All permissions in the system.
     */
    public function getPermissions(): array;

    /**
     * Returns the named permission.
     *
     * @param string $name The permission name.
     *
     * @return Permission|null The permission corresponding to the specified name. `null` is returned if no such
     * permission.
     */
    public function getPermissionByName(string $name): ?Permission;

    /**
     * Removes all permissions.
     * All parent child relations will be adjusted accordingly.
     */
    public function clearPermissions(): void;

    /**
     * Returns the child permissions and/or roles.
     *
     * @param string $name The parent name.
     *
     * @return Item[] The child permissions and/or roles.
     *
     * @psalm-return array<string,Item>
     */
    public function getChildrenByName(string $name): array;

    /**
     * Returns whether named parent has children.
     *
     * @param string $name The parent name.
     *
     * @return bool Whether named parent has children.
     */
    public function hasChildren(string $name): bool;

    /**
     * Adds an role or an permission as a child of another role or permission.
     *
     * @param Item $parent Parent to add child to.
     * @param Item $child Child to add.
     */
    public function addChild(Item $parent, Item $child): void;

    /**
     * Removes a child from its parent.
     * Note, the child role or permission is not deleted. Only the parent-child relationship is removed.
     *
     * @param Item $parent Parent to remove child from.
     * @param Item $child Child to remove.
     */
    public function removeChild(Item $parent, Item $child): void;

    /**
     * Removed all children form their parent.
     * Note, the children roles or permissions are not deleted. Only the parent-child relationships are removed.
     *
     * @param Item $parent Parent to remove children from.
     */
    public function removeChildren(Item $parent): void;

    /**
     * Returns all rules available in the system.
     *
     * @return RuleInterface[] The rules indexed by the rule names.
     */
    public function getRules(): array;

    /**
     * Returns the rule of the specified name.
     *
     * @param string $name The rule name.
     *
     * @return RuleInterface|null The rule object, or `null` if the specified name does not correspond to a rule.
     */
    public function getRuleByName(string $name): ?RuleInterface;

    /**
     * Removes the rule of the specified name from RBAC system.
     *
     * @param string $name The rule name.
     */
    public function removeRule(string $name): void;

    /**
     * Adds the rule to RBAC system.
     *
     * @param RuleInterface $rule The rule to add.
     */
    public function addRule(RuleInterface $rule): void;

    /**
     * Removes all rules.
     * All roles and permissions which have rules will be adjusted accordingly.
     */
    public function clearRules(): void;
}
