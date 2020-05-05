<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Manager;

use Yiisoft\Access\AccessCheckerInterface;
use Yiisoft\Rbac\Assignment;
use Yiisoft\Rbac\Exceptions\InvalidArgumentException;
use Yiisoft\Rbac\Exceptions\InvalidCallException;
use Yiisoft\Rbac\Exceptions\InvalidConfigException;
use Yiisoft\Rbac\Exceptions\InvalidValueException;
use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\Role;
use Yiisoft\Rbac\Rule;
use Yiisoft\Rbac\RuleFactoryInterface;
use Yiisoft\Rbac\Repository;

/**
 * Manager represents an authorization manager that stores authorization
 * information in terms of a PHP script file.
 *
 * The authorization data will be saved to and loaded from three files
 * specified by [[itemFile]], [[assignmentFile]] and [[ruleFile]].
 *
 * Manager is mainly suitable for authorization data that is not too big
 * (for example, the authorization data for a personal blog system).
 * Use [[DbManager]] for more complex authorization data.
 *
 * For more details and usage information on Manager, see the [guide article on security authorization](guide:security-authorization).
 */
class Manager implements AccessCheckerInterface
{
    private Repository $repository;
    private RuleFactoryInterface $ruleFactory;

    /**
     * @var array a list of role names that are assigned to every user automatically without calling [[assign()]].
     * Note that these roles are applied to users, regardless of their state of authentication.
     */
    protected array $defaultRoles = [];

    public function __construct(
        Repository $storage,
        RuleFactoryInterface $ruleFactory
    ) {
        $this->repository = $storage;
        $this->ruleFactory = $ruleFactory;
    }

    /**
     * @param mixed $userId
     * @param string $permissionName
     * @param array $parameters
     * @return bool
     * @throws InvalidConfigException
     */
    public function userHasPermission($userId, string $permissionName, array $parameters = []): bool
    {
        $assignments = $this->repository->getUserAssignments($userId);

        if (empty($assignments) && $this->defaultRolesIsEmpty()) {
            return false;
        }

        if ($this->repository->getPermissionByName($permissionName) === null) {
            return false;
        }

        return $this->userHasPermissionRecursive($userId, $permissionName, $parameters, $assignments);
    }

    /**
     * Checks the possibility of adding a child to parent.
     *
     * @param Item $parent the parent item
     * @param Item $child  the child item to be added to the hierarchy
     *
     * @return bool possibility of adding
     */
    public function canAddChild(Item $parent, Item $child): bool
    {
        return $parent->canBeParentOfItem($child) && !$this->detectLoop($parent, $child);
    }

    /**
     * Adds an item as a child of another item.
     *
     * @param Item $parent
     * @param Item $child
     *
     * @throws InvalidCallException
     */
    public function addChild(Item $parent, Item $child): void
    {
        if (!$this->hasItem($parent->getName()) || !$this->hasItem($child->getName())) {
            throw new InvalidArgumentException(
                "Either \"{$parent->getName()}\" or \"{$child->getName()}\" does not exist."
            );
        }

        if ($parent->isEqualName($child->getName())) {
            throw new InvalidArgumentException("Cannot add \"{$parent->getName()}\" as a child of itself.");
        }

        if (!$parent->canBeParentOfItem($child)) {
            throw new InvalidArgumentException(
                "Can not add \"{$child->getName()}\" role as a child of \"{$parent->getName()}\" permission."
            );
        }

        if ($this->detectLoop($parent, $child)) {
            throw new InvalidCallException(
                "Cannot add \"{$child->getName()}\" as a child of \"{$parent->getName()}\". A loop has been detected."
            );
        }

        if (isset($this->repository->getChildrenByName($parent->getName())[$child->getName()])) {
            throw new InvalidCallException(
                "The item \"{$parent->getName()}\" already has a child \"{$child->getName()}\"."
            );
        }

        $this->repository->addChildren($parent, $child);
    }

    /**
     * Removes a child from its parent.
     * Note, the child item is not deleted. Only the parent-child relationship is removed.
     *
     * @param Item $parent
     * @param Item $child
     *
     * @return void
     */
    public function removeChild(Item $parent, Item $child): void
    {
        if ($this->hasChild($parent, $child)) {
            $this->repository->removeChild($parent, $child);
        }
    }

    /**
     * Removed all children form their parent.
     * Note, the children items are not deleted. Only the parent-child relationships are removed.
     *
     * @param Item $parent
     *
     * @return void
     */
    public function removeChildren(Item $parent): void
    {
        if ($this->repository->hasChildren($parent->getName())) {
            $this->repository->removeChildren($parent);
        }
    }

    /**
     * Returns a value indicating whether the child already exists for the parent.
     *
     * @param Item $parent
     * @param Item $child
     *
     * @return bool whether `$child` is already a child of `$parent`
     */
    public function hasChild(Item $parent, Item $child): bool
    {
        return isset($this->repository->getChildrenByName($parent->getName())[$child->getName()]);
    }

    /**
     * Assigns a role or permission to a user.
     *
     * @param Item $item
     * @param string $userId the user ID
     *
     * @return Assignment the role or permission assignment information.
     * @throws \Exception if the role has already been assigned to the user
     *
     */
    public function assign(Item $item, string $userId): Assignment
    {
        if (!$this->hasItem($item->getName())) {
            throw new InvalidArgumentException("Unknown {$item->getType()} '{$item->getName()}'.");
        }

        if ($this->repository->getUserAssignmentsByName($userId, $item->getName()) !== null) {
            throw new InvalidArgumentException(
                "'{$item->getName()}' {$item->getType()} has already been assigned to user '$userId'."
            );
        }

        $this->repository->addAssignments($userId, $item);

        return $this->repository->getUserAssignmentsByName($userId, $item->getName());
    }

    /**
     * Revokes a role or a permission from a user.
     *
     * @param Item $item
     * @param string $userId the user ID
     *
     * @return void
     */
    public function revoke(Item $role, string $userId): void
    {
        if ($this->repository->getUserAssignmentsByName($userId, $role->getName()) !== null) {
            $this->repository->removeAssignments($userId, $role);
        }
    }

    /**
     * Revokes all roles and permissions from a user.
     *
     * @param string $userId the user ID
     *
     * @return void
     */
    public function revokeAll(string $userId): void
    {
        $this->repository->removeAllAssignments($userId);
    }

    /**
     * Returns the roles that are assigned to the user via [[assign()]].
     * Note that child roles that are not assigned directly to the user will not be returned.
     *
     * @param string $userId the user ID
     *
     * @return Role[] all roles directly assigned to the user. The array is indexed by the role names.
     */
    public function getRolesByUser(string $userId): array
    {
        $roles = $this->getDefaultRoleInstances();
        foreach ($this->repository->getUserAssignments($userId) as $name => $assignment) {
            $role = $this->repository->getRoleByName($assignment->getItemName());
            if ($role !== null) {
                $roles[$name] = $role;
            }
        }

        return $roles;
    }

    /**
     * Returns child roles of the role specified. Depth isn't limited.
     *
     * @param string $roleName name of the role to file child roles for
     *
     * @return Role[] Child roles. The array is indexed by the role names.
     * First element is an instance of the parent Role itself.
     *
     * @throws InvalidArgumentException if Role was not found that are getting by $roleName
     */
    public function getChildRoles(string $roleName): array
    {
        $role = $this->repository->getRoleByName($roleName);
        if ($role === null) {
            throw new InvalidArgumentException("Role \"$roleName\" not found.");
        }

        $result = [];
        $this->getChildrenRecursive($roleName, $result);

        $roles = [$roleName => $role];

        $roles += array_filter(
            $this->repository->getRoles(),
            static function (Role $roleItem) use ($result) {
                return array_key_exists($roleItem->getName(), $result);
            }
        );

        return $roles;
    }

    /**
     * Returns all permissions that the specified role represents.
     *
     * @param string $roleName the role name
     *
     * @return Permission[] all permissions that the role represents. The array is indexed by the permission names.
     */
    public function getPermissionsByRole(string $roleName): array
    {
        $result = [];
        $this->getChildrenRecursive($roleName, $result);

        if (empty($result)) {
            return [];
        }

        return $this->normalizePermissions($result);
    }

    /**
     * Returns all permissions that the user has.
     *
     * @param string $userId the user ID
     *
     * @return Permission[] all permissions that the user has. The array is indexed by the permission names.
     */
    public function getPermissionsByUser(string $userId): array
    {
        return array_merge(
            $this->getDirectPermissionsByUser($userId),
            $this->getInheritedPermissionsByUser($userId)
        );
    }

    /**
     * Returns all user IDs assigned to the role specified.
     *
     * @param string $roleName
     *
     * @return array array of user ID strings
     */
    public function getUserIdsByRole(string $roleName): array
    {
        $result = [];
        $roles = [$roleName];
        $this->getParentRolesRecursive($roleName, $roles);

        /**
         * @var $assignments Assignment[]
         */
        foreach ($this->repository->getAssignments() as $userID => $assignments) {
            foreach ($assignments as $userAssignment) {
                if (in_array($userAssignment->getItemName(), $roles, true)) {
                    $result[] = (string)$userID;
                }
            }
        }

        return $result;
    }

    /**
     * @param Role $role
     */
    public function addRole(Role $role): void
    {
        $this->createItemRuleIfNotExist($role);
        $this->addItem($role);
    }

    /**
     * @param Permission $permission
     */
    public function addPermission(Permission $permission): void
    {
        $this->createItemRuleIfNotExist($permission);
        $this->addItem($permission);
    }

    /**
     * @param Rule $rule
     */
    public function addRule(Rule $rule): void
    {
        $this->repository->addRule($rule);
    }

    /**
     * @param Role $role
     */
    public function removeRole(Role $role): void
    {
        $this->removeItem($role);
    }

    /**
     * @param Permission $permission
     */
    public function removePermission(Permission $permission): void
    {
        $this->removeItem($permission);
    }

    /**
     * @param Rule $rule
     */
    public function removeRule(Rule $rule): void
    {
        if ($this->repository->getRuleByName($rule->getName()) !== null) {
            $this->repository->removeRule($rule->getName());
        }
    }

    /**
     * @param string $name
     * @param Role $role
     */
    public function updateRole(string $name, Role $role): void
    {
        $this->createItemRuleIfNotExist($role);
        $this->repository->updateItem($name, $role);
    }

    /**
     * @param string $name
     * @param Permission $permission
     */
    public function updatePermission(string $name, Permission $permission): void
    {
        $this->createItemRuleIfNotExist($permission);
        $this->repository->updateItem($name, $permission);
    }

    /**
     * @param string $name
     * @param Rule $rule
     */
    public function updateRule(string $name, Rule $rule): void
    {
        if ($rule->getName() !== $name) {
            $this->repository->removeRule($name);
        }
        $this->repository->addRule($rule);
    }

    /**
     * Set default roles.
     *
     * @param string[]|callable $roles either array of roles or a callable returning it
     *
     * @return $this
     * @throws InvalidArgumentException when $roles is neither array nor Closure
     * @throws InvalidValueException when Closure return is not an array
     */
    public function setDefaultRoles($roles): self
    {
        if (is_array($roles)) {
            $this->defaultRoles = $roles;
            return $this;
        }

        if ($roles instanceof \Closure) {
            $roles = $roles();
            if (!is_array($roles)) {
                throw new InvalidValueException('Default roles closure must return an array');
            }
            $this->defaultRoles = $roles;
            return $this;
        }

        throw new InvalidArgumentException('Default roles must be either an array or a callable');
    }

    /**
     * Get default roles.
     *
     * @return string[] default roles
     */
    public function getDefaultRoles(): array
    {
        return $this->defaultRoles;
    }

    /**
     * Returns defaultRoles as array of Role objects.
     *
     * @return Role[] default roles. The array is indexed by the role names
     *
     */
    public function getDefaultRoleInstances(): array
    {
        $result = [];
        foreach ($this->defaultRoles as $roleName) {
            $result[$roleName] = new Role($roleName);
        }

        return $result;
    }

    /**
     * Executes the rule associated with the specified auth item.
     *
     * If the item does not specify a rule, this method will return true. Otherwise, it will
     * return the value of [[Rule::execute()]].
     *
     * @param string $user the user ID. This should be a string representing
     * the unique identifier of a user.
     * @param Item $item the auth item that needs to execute its rule
     * @param array $params parameters passed to {@see AccessCheckerInterface::userHasPermission()} and will be passed to the rule
     *
     * @return bool the return value of {@see Rule::execute()}. If the auth item does not specify a rule, true will be
     * returned.
     * @throws InvalidConfigException if the auth item has an invalid rule.
     *
     */
    protected function executeRule(string $user, Item $item, array $params): bool
    {
        if (!$item->hasRuleName()) {
            return true;
        }
        $rule = $this->repository->getRuleByName($item->getRuleName());
        if ($rule === null) {
            throw new InvalidConfigException("Rule not found: {$item->getRuleName()}");
        }

        return $rule->execute($user, $item, $params);
    }

    /**
     * @return bool
     */
    protected function defaultRolesIsEmpty(): bool
    {
        return empty($this->defaultRoles);
    }

    protected function createItemRuleIfNotExist(Item $item): void
    {
        if ($item->hasRuleName() && $this->repository->getRuleByName($item->getRuleName()) === null) {
            $rule = $this->createRule($item->getRuleName());
            $this->addRule($rule);
        }
    }

    protected function addItem(Item $item): void
    {
        $time = time();
        if (!$item->hasCreatedAt()) {
            $item = $item->withCreatedAt($time);
        }
        if (!$item->hasUpdatedAt()) {
            $item = $item->withUpdatedAt($time);
        }

        $this->repository->addItem($item);
    }


    protected function createRule(string $name): Rule
    {
        return $this->ruleFactory->create($name);
    }

    private function getParentRolesRecursive(string $roleName, &$result): void
    {
        /**
         * @var $items Item[]
         */
        foreach ($this->repository->getChildren() as $parentRole => $items) {
            foreach ($items as $item) {
                if ($item->getName() === $roleName) {
                    $result[] = $parentRole;
                    $this->getParentRolesRecursive($parentRole, $result);
                    break;
                }
            }
        }
    }

    protected function hasItem(string $name): bool
    {
        return $this->repository->getItemByName($name) !== null;
    }

    protected function normalizePermissions(array $permissions): array
    {
        $normalizePermissions = [];
        foreach (array_keys($permissions) as $itemName) {
            $permission = $this->repository->getPermissionByName($itemName);
            if ($permission !== null) {
                $normalizePermissions[$itemName] = $permission;
            }
        }

        return $normalizePermissions;
    }


    /**
     * Returns all permissions that are directly assigned to user.
     *
     * @param string $userId the user ID (see [[\yii\web\User::id]])
     *
     * @return Permission[] all direct permissions that the user has. The array is indexed by the permission names.
     */
    protected function getDirectPermissionsByUser(string $userId): array
    {
        $permissions = [];
        foreach ($this->repository->getUserAssignments($userId) as $name => $assignment) {
            $permission = $this->repository->getPermissionByName($assignment->getItemName());
            if ($permission !== null) {
                $permissions[$name] = $permission;
            }
        }

        return $permissions;
    }

    /**
     * Returns all permissions that the user inherits from the roles assigned to him.
     *
     * @param string $userId the user ID (see [[\yii\web\User::id]])
     *
     * @return Permission[] all inherited permissions that the user has. The array is indexed by the permission names.
     */
    protected function getInheritedPermissionsByUser(string $userId): array
    {
        $assignments = $this->repository->getUserAssignments($userId);
        $result = [];
        foreach (array_keys($assignments) as $roleName) {
            $this->getChildrenRecursive($roleName, $result);
        }

        if (empty($result)) {
            return [];
        }

        return $this->normalizePermissions($result);
    }

    protected function removeItem(Item $item): void
    {
        if ($this->hasItem($item->getName())) {
            $this->repository->removeItem($item);
        }
    }

    /**
     * Performs access check for the specified user.
     * This method is internally called by [[checkAccess()]].
     *
     * @param string $user the user ID. This should br a string representing the unique identifier of a user.
     * @param string $itemName the name of the permission or role that need access check
     * @param array $params name-value pairs that would be passed to rules associated
     * with the permissions and roles assigned to the user. A param with name 'user' is
     * added to this array, which holds the value of `$userId`.
     * @param Assignment[] $assignments the assignments to the specified user
     *
     * @return bool whether the operations can be performed by the user.
     * @throws InvalidConfigException
     */
    protected function userHasPermissionRecursive(
        string $user,
        string $itemName,
        array $params,
        array $assignments
    ): bool {
        if (!$this->hasItem($itemName)) {
            return false;
        }

        $item = $this->repository->getItems()[$itemName];

        if (!$this->executeRule($user, $item, $params)) {
            return false;
        }

        if (isset($assignments[$itemName])) {
            return true;
        }

        foreach ($this->repository->getChildren() as $parentName => $children) {
            if (isset($children[$itemName]) && $this->userHasPermissionRecursive(
                    $user,
                    $parentName,
                    $params,
                    $assignments
                )) {
                return true;
            }
        }

        return false;
    }

    /**
     * Checks whether there is a loop in the authorization item hierarchy.
     *
     * @param Item $parent parent item
     * @param Item $child the child item that is to be added to the hierarchy
     *
     * @return bool whether a loop exists
     */
    protected function detectLoop(Item $parent, Item $child): bool
    {
        if ($child->isEqualName($parent->getName())) {
            return true;
        }

        $children = $this->repository->getChildrenByName($child->getName());
        if (empty($children)) {
            return false;
        }

        foreach ($children as $groupChild) {
            if ($this->detectLoop($parent, $groupChild)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Recursively finds all children and grand children of the specified item.
     *
     * @param string $name the name of the item whose children are to be looked for.
     * @param array $result the children and grand children (in array keys)
     */
    protected function getChildrenRecursive(string $name, &$result): void
    {
        $children = $this->repository->getChildrenByName($name);
        if (empty($children)) {
            return;
        }

        foreach ($children as $childName => $child) {
            $result[$childName] = true;
            $this->getChildrenRecursive($childName, $result);
        }
    }
}
