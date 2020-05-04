<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Manager;

use Yiisoft\Rbac\Assignment;
use Yiisoft\Rbac\Exceptions\InvalidArgumentException;
use Yiisoft\Rbac\Exceptions\InvalidCallException;
use Yiisoft\Rbac\Exceptions\InvalidConfigException;
use Yiisoft\Rbac\Exceptions\InvalidValueException;
use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\ItemInterface;
use Yiisoft\Rbac\ManagerInterface;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\Role;
use Yiisoft\Rbac\Rule;
use Yiisoft\Rbac\RuleFactoryInterface;
use Yiisoft\Rbac\Storage;

/**
 * PhpManager represents an authorization manager that stores authorization
 * information in terms of a PHP script file.
 *
 * The authorization data will be saved to and loaded from three files
 * specified by [[itemFile]], [[assignmentFile]] and [[ruleFile]].
 *
 * PhpManager is mainly suitable for authorization data that is not too big
 * (for example, the authorization data for a personal blog system).
 * Use [[DbManager]] for more complex authorization data.
 *
 * For more details and usage information on PhpManager, see the [guide article on security authorization](guide:security-authorization).
 */
class PhpManager implements ManagerInterface
{
    private Storage $storage;
    private RuleFactoryInterface $ruleFactory;

    /**
     * @var array a list of role names that are assigned to every user automatically without calling [[assign()]].
     * Note that these roles are applied to users, regardless of their state of authentication.
     */
    protected array $defaultRoles = [];

    public function __construct(
        Storage $storage,
        RuleFactoryInterface $ruleFactory
    ) {
        $this->storage = $storage;
        $this->ruleFactory = $ruleFactory;
    }

    /**
     * @param string $userId
     * @return Assignment[]
     */
    public function getAssignments(string $userId): array
    {
        return $this->storage->getAssignmentsByUser($userId);
    }

    public function hasAssignments(string $itemName): bool
    {
        return $this->storage->assignmentExist($itemName);
    }

    public function userHasPermission($userId, string $permissionName, array $parameters = []): bool
    {
        $assignments = $this->getAssignments($userId);

        if ($this->hasNoAssignments($assignments)) {
            return false;
        }

        if ($this->getPermission($permissionName) === null) {
            return false;
        }

        return $this->userHasPermissionRecursive($userId, $permissionName, $parameters, $assignments);
    }

    public function canAddChild(Item $parent, Item $child): bool
    {
        if ($this->isPermission($parent) && $this->isRole($child)) {
            return false;
        }
        return !$this->detectLoop($parent, $child);
    }

    public function addChild(Item $parent, Item $child): void
    {
        if (!$this->hasItem($parent->getName()) || !$this->hasItem($child->getName())) {
            throw new InvalidArgumentException(
                "Either \"{$parent->getName()}\" or \"{$child->getName()}\" does not exist."
            );
        }

        if ($parent->getName() === $child->getName()) {
            throw new InvalidArgumentException("Cannot add \"{$parent->getName()}\" as a child of itself.");
        }

        if ($this->isPermission($parent) && $this->isRole($child)) {
            throw new InvalidArgumentException(
                "Can not add \"{$child->getName()}\" role as a child of \"{$parent->getName()}\" permission."
            );
        }

        if ($this->detectLoop($parent, $child)) {
            throw new InvalidCallException(
                "Cannot add \"{$child->getName()}\" as a child of \"{$parent->getName()}\". A loop has been detected."
            );
        }

        if (isset($this->storage->getChildren()[$parent->getName()][$child->getName()])) {
            throw new InvalidCallException(
                "The item \"{$parent->getName()}\" already has a child \"{$child->getName()}\"."
            );
        }

        $this->storage->addChildren($parent, $child);
    }

    public function removeChild(Item $parent, Item $child): void
    {
        if (isset($this->storage->getChildren()[$parent->getName()][$child->getName()])) {
            $this->storage->removeChild($parent, $child);
        }
    }

    public function removeChildren(Item $parent): void
    {
        if (isset($this->storage->getChildren()[$parent->getName()])) {
            $this->storage->removeChildren($parent);
        }
    }

    public function hasChild(Item $parent, Item $child): bool
    {
        return isset($this->storage->getChildren()[$parent->getName()][$child->getName()]);
    }

    public function assign(Item $item, string $userId): Assignment
    {
        $itemName = $this->getTypeByItem($item);

        if (!$this->hasItem($item->getName())) {
            throw new InvalidArgumentException("Unknown {$itemName} '{$item->getName()}'.");
        }

        if (isset($this->storage->getAssignmentsByUser($userId)[$item->getName()])) {
            throw new InvalidArgumentException(
                "'{$item->getName()}' {$itemName} has already been assigned to user '$userId'."
            );
        }

        $this->storage->addAssignments($userId, $item);

        return $this->storage->getAssignmentsByUser($userId)[$item->getName()];
    }

    public function revoke(Item $role, string $userId): void
    {
        if (isset($this->storage->getAssignmentsByUser($userId)[$role->getName()])) {
            $this->storage->removeAssignments($userId, $role);
        }
    }

    public function revokeAll(string $userId): void
    {
        $this->storage->removeAllAssignments($userId);
    }

    public function getAssignment(string $roleName, string $userId): ?Assignment
    {
        return $this->storage->getAssignmentsByUser($userId)[$roleName] ?? null;
    }

    public function getRule(string $name): ?Rule
    {
        return $this->storage->getRulesByName($name);
    }

    public function getRules(): array
    {
        return $this->storage->getRules();
    }

    public function getRolesByUser(string $userId): array
    {
        $roles = $this->getDefaultRoleInstances();
        foreach ($this->getAssignments($userId) as $name => $assignment) {
            $role = $this->storage->getRoleByName($assignment->getItemName());
            if ($role !== null) {
                $roles[$name] = $role;
            }
        }

        return $roles;
    }

    public function getChildRoles(string $roleName): array
    {
        $role = $this->getRole($roleName);
        if ($role === null) {
            throw new InvalidArgumentException("Role \"$roleName\" not found.");
        }

        $result = [];
        $this->getChildrenRecursive($roleName, $result);

        $roles = [$roleName => $role];

        $roles += array_filter(
            $this->getRoles(),
            static function (Role $roleItem) use ($result) {
                return array_key_exists($roleItem->getName(), $result);
            }
        );

        return $roles;
    }

    public function getPermissionsByRole(string $roleName): array
    {
        $result = [];
        $this->getChildrenRecursive($roleName, $result);

        if (empty($result)) {
            return [];
        }

        return $this->normalizePermissions($result);
    }

    public function getPermissionsByUser(string $userId): array
    {
        return array_merge(
            $this->getDirectPermissionsByUser($userId),
            $this->getInheritedPermissionsByUser($userId)
        );
    }

    public function getChildren(string $name): array
    {
        return $this->storage->getChildren()[$name] ?? [];
    }

    public function removeAll(): void
    {
        $this->storage->clear();
    }

    public function removeAllPermissions(): void
    {
        $this->storage->removeAllItems(Item::TYPE_PERMISSION);
    }

    public function removeAllRoles(): void
    {
        $this->storage->removeAllItems(Item::TYPE_ROLE);
    }

    public function removeAllRules(): void
    {
        $this->storage->clearRules();
    }

    public function removeAllAssignments(): void
    {
        $this->storage->clearAssignments();
    }

    public function getUserIdsByRole(string $roleName): array
    {
        $result = [];
        $roles = [$roleName];
        $this->getParentRolesRecursive($roleName, $roles);

        /**
         * @var $assignments Assignment[]
         */
        foreach ($this->storage->getAssignments() as $userID => $assignments) {
            foreach ($assignments as $userAssignment) {
                if (in_array($userAssignment->getItemName(), $roles, true)) {
                    $result[] = (string)$userID;
                }
            }
        }

        return $result;
    }

    /**
     * @param ItemInterface|Item|Rule $item
     */
    public function add(ItemInterface $item): void
    {
        if ($this->isItem($item)) {
            $this->createItemRuleIfNotExist($item);
            $this->addItem($item);
            return;
        }

        if ($this->isRule($item)) {
            $this->storage->addRule($item);
            return;
        }

        throw new InvalidArgumentException('Adding unsupported item type.');
    }

    /**
     * @param ItemInterface|Item|Rule $item
     */
    public function remove(ItemInterface $item): void
    {
        if ($this->isItem($item)) {
            $this->removeItem($item);
            return;
        }

        if ($this->isRule($item)) {
            $this->removeRule($item);
            return;
        }

        throw new InvalidArgumentException('Removing unsupported item type.');
    }

    /**
     * @param string $name
     * @param ItemInterface|Item|Rule $object
     */
    public function update(string $name, ItemInterface $object): void
    {
        if ($this->isItem($object)) {
            $this->createItemRuleIfNotExist($object);
            $this->storage->updateItem($name, $object);
            return;
        }

        if ($this->isRule($object)) {
            $this->updateRule($name, $object);
            return;
        }

        throw new InvalidArgumentException('Updating unsupported item type.');
    }

    public function getRoles(): array
    {
        return $this->storage->getRoles();
    }

    public function getRole(string $name): ?Role
    {
        return $this->storage->getRoleByName($name);
    }

    public function getPermission(string $name): ?Permission
    {
        return $this->storage->getPermissionByName($name);
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
     * @return array
     */
    public function getPermissions(): array
    {
        return $this->storage->getPermissions();
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
        if ($item->getRuleName() === null) {
            return true;
        }
        $rule = $this->getRule($item->getRuleName());
        if ($rule === null) {
            throw new InvalidConfigException("Rule not found: {$item->getRuleName()}");
        }

        return $rule->execute($user, $item, $params);
    }

    /**
     * Checks whether array of $assignments is empty and [[defaultRoles]] property is empty as well.
     *
     * @param Assignment[] $assignments array of user's assignments
     *
     * @return bool whether array of $assignments is empty and [[defaultRoles]] property is empty as well
     */
    protected function hasNoAssignments(array $assignments): bool
    {
        return empty($assignments) && empty($this->defaultRoles);
    }

    protected function isPermission(?ItemInterface $item): bool
    {
        return $item !== null && $item instanceof Permission;
    }

    protected function isRole(?ItemInterface $item): bool
    {
        return $item !== null && $item instanceof Role;
    }

    protected function isItem(?ItemInterface $item): bool
    {
        return $item !== null && $item instanceof Item;
    }

    protected function isRule(?ItemInterface $item): bool
    {
        return $item !== null && $item instanceof Rule;
    }

    protected function createItemRuleIfNotExist(Item $item): void
    {
        if ($item->getRuleName() && $this->getRule($item->getRuleName()) === null) {
            $rule = $this->createRule($item->getRuleName());
            $this->storage->addRule($rule);
        }
    }

    protected function removeRule(Rule $rule): void
    {
        if (isset($this->storage->getRules()[$rule->getName()])) {
            $this->storage->removeRule($rule->getName());
            foreach ($this->storage->getItems() as $item) {
                if ($item->getRuleName() === $rule->getName()) {
                    $item = $item->withRuleName(null);
                    $this->storage->updateItem($item->getName(), $item);
                }
            }
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

        $this->storage->addItem($item);
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
        foreach ($this->storage->getChildren() as $parentRole => $items) {
            foreach ($items as $item) {
                if ($item->getName() === $roleName) {
                    $result[] = $parentRole;
                    $this->getParentRolesRecursive($parentRole, $result);
                    break;
                }
            }
        }
    }

    protected function getTypeByItem(Item $item): string
    {
        if ($this->isRole($item) || $this->isPermission($item)) {
            return $item->getType();
        }

        return 'authorization item';
    }

    protected function hasItem(string $name): bool
    {
        return isset($this->storage->getItems()[$name]);
    }

    protected function normalizePermissions(array $permissions): array
    {
        $normalizePermissions = [];
        foreach (array_keys($permissions) as $itemName) {
            if ($this->hasItem($itemName) && $this->isPermission($this->storage->getItems()[$itemName])) {
                $normalizePermissions[$itemName] = $this->storage->getItems()[$itemName];
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
        foreach ($this->getAssignments($userId) as $name => $assignment) {
            $permission = $this->storage->getItems()[$assignment->getItemName()];
            if ($permission->getType() === Item::TYPE_PERMISSION) {
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
        $assignments = $this->getAssignments($userId);
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
            $this->storage->removeItem($item);
        }
    }

    protected function updateRule(string $name, Rule $rule): void
    {
        if ($rule->getName() !== $name) {
            $this->storage->removeRule($name);
        }
        $this->storage->addRule($rule);
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

        $item = $this->storage->getItems()[$itemName];

        if (!$this->executeRule($user, $item, $params)) {
            return false;
        }

        if (isset($assignments[$itemName])) {
            return true;
        }

        foreach ($this->storage->getChildren() as $parentName => $children) {
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
        if ($child->getName() === $parent->getName()) {
            return true;
        }
        if (!isset($this->storage->getChildren()[$child->getName()], $this->storage->getItems()[$parent->getName()])) {
            return false;
        }
        foreach ($this->storage->getChildren()[$child->getName()] as $grandchild) {
            /* @var $grandchild Item */
            if ($this->detectLoop($parent, $grandchild)) {
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
        if (isset($this->storage->getChildren()[$name])) {
            foreach ($this->storage->getChildren()[$name] as $child) {
                $result[$child->getName()] = true;
                $this->getChildrenRecursive($child->getName(), $result);
            }
        }
    }
}
