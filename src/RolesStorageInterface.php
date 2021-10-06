<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

/**
 * RolesStorageInterface represents a storage for RBAC items used in {@see Manager}.
 *
 * @package Yiisoft\Rbac
 */
interface RolesStorageInterface
{
    /**
     * Removes all authorization data, including roles, permissions, and rules.
     */
    public function clear(): void;

    /**
     * Returns all items in the system.
     *
     * @return Item[] All items in the system.
     */
    public function getItems(): array;

    /**
     * Returns the named item.
     *
     * @param string $name The item name.
     *
     * @return Item|null The item corresponding to the specified name. Null is returned if no such item.
     */
    public function getItemByName(string $name): ?Item;

    /**
     * Adds the item to RBAC system.
     *
     * @param Item $item The item to add.
     */
    public function addItem(Item $item): void;

    /**
     * Updates the specified role, permission or rule in the system.
     *
     * @param string $name The old name of the role, permission or rule.
     * @param Item $item Modified item.
     */
    public function updateItem(string $name, Item $item): void;

    /**
     * Removes a role, permission or rule from the RBAC system.
     *
     * @param Item $item Item to remove.
     */
    public function removeItem(Item $item): void;

    /**
     * @return array
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
     * @return Role|null The role corresponding to the specified name. Null is returned if no such role.
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
     * @return Permission|null The permission corresponding to the specified name. Null is returned if no such permission.
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
     * Adds an item as a child of another item.
     *
     * @param Item $parent Parent to add child to.
     * @param Item $child Child to add.
     */
    public function addChild(Item $parent, Item $child): void;

    /**
     * Removes a child from its parent.
     * Note, the child item is not deleted. Only the parent-child relationship is removed.
     *
     * @param Item $parent Parent to remove child from.
     * @param Item $child Child to remove.
     */
    public function removeChild(Item $parent, Item $child): void;

    /**
     * Removed all children form their parent.
     * Note, the children items are not deleted. Only the parent-child relationships are removed.
     *
     * @param Item $parent Parent to remove children from.
     */
    public function removeChildren(Item $parent): void;

    /**
     * Returns all rules available in the system.
     *
     * @return Rule[] The rules indexed by the rule names.
     */
    public function getRules(): array;

    /**
     * Returns the rule of the specified name.
     *
     * @param string $name The rule name.
     *
     * @return Rule|null The rule object, or null if the specified name does not correspond to a rule.
     */
    public function getRuleByName(string $name): ?Rule;

    /**
     * Removes the rule of the specified name from RBAC system.
     *
     * @param string $name The rule name.
     */
    public function removeRule(string $name): void;

    /**
     * Adds the rule to RBAC system.
     *
     * @param Rule $rule The rule to add.
     */
    public function addRule(Rule $rule): void;

    /**
     * Removes all rules.
     * All roles and permissions which have rules will be adjusted accordingly.
     */
    public function clearRules(): void;
}
