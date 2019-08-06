<?php
namespace Yiisoft\Rbac;

use Yiisoft\Access\CheckAccessInterface;

/**
 * For more details and usage information on ManagerInterface, see the [guide article on security authorization](guide:security-authorization).
 */
interface ManagerInterface extends CheckAccessInterface
{
    /**
     * Creates a new Role object.
     * Note that the newly created role is not added to the RBAC system yet.
     * You must fill in the needed data and call [[add()]] to add it to the system.
     *
     * @param string $name the role name
     *
     * @return Role the new Role object
     */
    public function createRole(string $name): Role;

    /**
     * Creates a new Permission object.
     * Note that the newly created permission is not added to the RBAC system yet.
     * You must fill in the needed data and call [[add()]] to add it to the system.
     *
     * @param string $name the permission name
     *
     * @return Permission the new Permission object
     */
    public function createPermission(string $name): Permission;

    /**
     * Adds a role, permission or rule to the RBAC system.
     *
     * @param \Yiisoft\Rbac\BaseItem $object
     *
     * @return void
     */
    public function add(BaseItem $object): void;

    /**
     * Removes a role, permission or rule from the RBAC system.
     *
     * @param \Yiisoft\Rbac\BaseItem $object
     *
     * @return void
     */
    public function remove(BaseItem $object): void;

    /**
     * Updates the specified role, permission or rule in the system.
     *
     * @param string                 $name the old name of the role, permission or rule
     * @param \Yiisoft\Rbac\BaseItem $object
     *
     * @return void
     */
    public function update(string $name, BaseItem $object): void;

    /**
     * Returns the named role.
     *
     * @param string $name the role name.
     *
     * @return null|Role the role corresponding to the specified name. Null is returned if no such role.
     */
    public function getRole(string $name): ?Role;

    /**
     * Returns all roles in the system.
     *
     * @return Role[] all roles in the system. The array is indexed by the role names.
     */
    public function getRoles(): array;

    /**
     * Returns the roles that are assigned to the user via [[assign()]].
     * Note that child roles that are not assigned directly to the user will not be returned.
     *
     * @param string|int $userId the user ID (see [[\yii\web\User::id]])
     *
     * @return Role[] all roles directly assigned to the user. The array is indexed by the role names.
     */
    public function getRolesByUser(string $userId): array;

    /**
     * Returns child roles of the role specified. Depth isn't limited.
     *
     * @param string $roleName name of the role to file child roles for
     *
     * @return Role[] Child roles. The array is indexed by the role names.
     *                First element is an instance of the parent Role itself.
     *
     * @throws \Yiisoft\Rbac\Exceptions\InvalidArgumentException if Role was not found that are getting by $roleName
     *
     * @since 2.0.10
     */
    public function getChildRoles(string $roleName): array;

    /**
     * Returns the named permission.
     *
     * @param string $name the permission name.
     *
     * @return null|Permission the permission corresponding to the specified name. Null is returned if no such
     *                         permission.
     */
    public function getPermission(string $name): ?Permission;

    /**
     * Returns all permissions in the system.
     *
     * @return Permission[] all permissions in the system. The array is indexed by the permission names.
     */
    public function getPermissions(): array;

    /**
     * Returns all permissions that the specified role represents.
     *
     * @param string $roleName the role name
     *
     * @return Permission[] all permissions that the role represents. The array is indexed by the permission names.
     */
    public function getPermissionsByRole(string $roleName): array;

    /**
     * Returns all permissions that the user has.
     *
     * @param string $userId the user ID (see [[\yii\web\User::id]])
     *
     * @return Permission[] all permissions that the user has. The array is indexed by the permission names.
     */
    public function getPermissionsByUser(string $userId): array;

    /**
     * Returns the rule of the specified name.
     *
     * @param string $name the rule name
     *
     * @return null|Rule the rule object, or null if the specified name does not correspond to a rule.
     */
    public function getRule(string $name): ?Rule;

    /**
     * Returns all rules available in the system.
     *
     * @return Rule[] the rules indexed by the rule names
     */
    public function getRules(): array;

    /**
     * Checks the possibility of adding a child to parent.
     *
     * @param Item $parent the parent item
     * @param Item $child  the child item to be added to the hierarchy
     *
     * @return bool possibility of adding
     *
     * @since 2.0.8
     */
    public function canAddChild(Item $parent, Item $child): bool;

    /**
     * Adds an item as a child of another item.
     *
     * @param Item $parent
     * @param Item $child
     *
     * @return void whether the child successfully added
     */
    public function addChild(Item $parent, Item $child): void;

    /**
     * Removes a child from its parent.
     * Note, the child item is not deleted. Only the parent-child relationship is removed.
     *
     * @param Item $parent
     * @param Item $child
     *
     * @return void
     */
    public function removeChild(Item $parent, Item $child): void;

    /**
     * Removed all children form their parent.
     * Note, the children items are not deleted. Only the parent-child relationships are removed.
     *
     * @param Item $parent
     *
     * @return void
     */
    public function removeChildren(Item $parent): void;

    /**
     * Returns a value indicating whether the child already exists for the parent.
     *
     * @param Item $parent
     * @param Item $child
     *
     * @return bool whether `$child` is already a child of `$parent`
     */
    public function hasChild(Item $parent, Item $child): bool;

    /**
     * Returns the child permissions and/or roles.
     *
     * @param string $name the parent name
     *
     * @return Item[] the child permissions and/or roles
     */
    public function getChildren(string $name): array;

    /**
     * Assigns a role to a user.
     *
     * @param Role|Permission $role
     * @param string          $userId the user ID (see [[\yii\web\User::id]])
     *
     * @return Assignment the role assignment information.
     * @throws \Exception if the role has already been assigned to the user
     *
     */
    public function assign(Item $role, string $userId): Assignment;

    /**
     * Revokes a role from a user.
     *
     * @param \Yiisoft\Rbac\Item $role
     * @param string|int         $userId the user ID (see [[\yii\web\User::id]])
     *
     * @return void
     */
    public function revoke(Item $role, string $userId): void;

    /**
     * Revokes all roles from a user.
     *
     * @param mixed $userId the user ID (see [[\yii\web\User::id]])
     *
     * @return void
     */
    public function revokeAll(string $userId): void;

    /**
     * Returns the assignment information regarding a role and a user.
     *
     * @param string     $roleName the role name
     * @param string|int $userId   the user ID (see [[\yii\web\User::id]])
     *
     * @return null|Assignment the assignment information. Null is returned if
     *                         the role is not assigned to the user.
     */
    public function getAssignment(string $roleName, string $userId): Assignment;

    /**
     * Returns all role assignment information for the specified user.
     *
     * @param string|int $userId the user ID (see [[\yii\web\User::id]])
     *
     * @return Assignment[] the assignments indexed by role names. An empty array will be
     *                      returned if there is no role assigned to the user.
     */
    public function getAssignments(string $userId): array;

    /**
     * Returns all user IDs assigned to the role specified.
     *
     * @param string $roleName
     *
     * @return array array of user ID strings
     *
     * @since 2.0.7
     */
    public function getUserIdsByRole(string $roleName): array;

    /**
     * Removes all authorization data, including roles, permissions, rules, and assignments.
     */
    public function removeAll(): void;

    /**
     * Removes all permissions.
     * All parent child relations will be adjusted accordingly.
     */
    public function removeAllPermissions(): void;

    /**
     * Removes all roles.
     * All parent child relations will be adjusted accordingly.
     */
    public function removeAllRoles(): void;

    /**
     * Removes all rules.
     * All roles and permissions which have rules will be adjusted accordingly.
     */
    public function removeAllRules(): void;

    /**
     * Removes all role assignments.
     */
    public function removeAllAssignments(): void;
}
