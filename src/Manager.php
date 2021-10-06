<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

use InvalidArgumentException;
use RuntimeException;
use Yiisoft\Access\AccessCheckerInterface;

/**
 * An authorization manager that helps with building RBAC hierarchy and checking for permissions.
 */
final class Manager implements AccessCheckerInterface
{
    private RolesStorageInterface $rolesStorage;
    private AssignmentsStorageInterface $assignmentsStorage;
    private RuleFactoryInterface $ruleFactory;

    /**
     * @var array a list of role names that are assigned to every user automatically without calling {@see assign()}.
     * Note that these roles are applied to users, regardless of their state of authentication.
     */
    private array $defaultRoles = [];

    public function __construct(RolesStorageInterface $rolesStorage, AssignmentsStorageInterface $assignmentsStorage, RuleFactoryInterface $ruleFactory)
    {
        $this->rolesStorage = $rolesStorage;
        $this->assignmentsStorage = $assignmentsStorage;
        $this->ruleFactory = $ruleFactory;
    }

    public function userHasPermission($userId, string $permissionName, array $parameters = []): bool
    {
        if (!is_string($userId) && !is_int($userId)) {
            throw new \InvalidArgumentException(sprintf('userId must be a string or an int, %s given.', gettype($userId)));
        }

        $userId = (string) $userId;
        $assignments = $this->assignmentsStorage->getUserAssignments($userId);

        if (empty($assignments) && empty($this->defaultRoles)) {
            return false;
        }

        if ($this->rolesStorage->getPermissionByName($permissionName) === null) {
            return false;
        }

        return $this->userHasPermissionRecursive($userId, $permissionName, $parameters, $assignments);
    }

    /**
     * Checks the possibility of adding a child to parent.
     *
     * @param Item $parent The parent item.
     * @param Item $child The child item to be added to the hierarchy.
     *
     * @return bool Whether it is possible to add the child to the parent.
     */
    public function canAddChild(Item $parent, Item $child): bool
    {
        return $this->canBeParent($parent, $child) && !$this->detectLoop($parent, $child);
    }

    /**
     * Adds an item as a child of another item.
     *
     * @param Item $parent
     * @param Item $child
     *
     * @throws RuntimeException
     * @throws InvalidArgumentException
     */
    public function addChild(Item $parent, Item $child): void
    {
        if (!$this->hasItem($parent->getName())) {
            throw new InvalidArgumentException(
                sprintf('Either "%s" does not exist.', $parent->getName())
            );
        }

        if (!$this->hasItem($child->getName())) {
            throw new InvalidArgumentException(
                sprintf('Either "%s" does not exist.', $child->getName())
            );
        }

        if ($parent->getName() === $child->getName()) {
            throw new InvalidArgumentException(sprintf('Cannot add "%s" as a child of itself.', $parent->getName()));
        }

        if (!$this->canBeParent($parent, $child)) {
            throw new InvalidArgumentException(
                sprintf('Can not add "%s" role as a child of "%s" permission.', $child->getName(), $parent->getName())
            );
        }

        if ($this->detectLoop($parent, $child)) {
            throw new RuntimeException(
                sprintf(
                    'Cannot add "%s" as a child of "%s". A loop has been detected.',
                    $child->getName(),
                    $parent->getName()
                )
            );
        }

        if (isset($this->rolesStorage->getChildrenByName($parent->getName())[$child->getName()])) {
            throw new RuntimeException(
                sprintf('The item "%s" already has a child "%s".', $parent->getName(), $child->getName())
            );
        }

        $this->rolesStorage->addChild($parent, $child);
    }

    /**
     * Removes a child from its parent.
     * Note, the child item is not deleted. Only the parent-child relationship is removed.
     *
     * @param Item $parent
     * @param Item $child
     */
    public function removeChild(Item $parent, Item $child): void
    {
        if ($this->hasChild($parent, $child)) {
            $this->rolesStorage->removeChild($parent, $child);
        }
    }

    /**
     * Removed all children form their parent.
     * Note, the children items are not deleted. Only the parent-child relationships are removed.
     *
     * @param Item $parent
     */
    public function removeChildren(Item $parent): void
    {
        if ($this->rolesStorage->hasChildren($parent->getName())) {
            $this->rolesStorage->removeChildren($parent);
        }
    }

    /**
     * Returns a value indicating whether the child already exists for the parent.
     *
     * @param Item $parent
     * @param Item $child
     *
     * @return bool Whether `$child` is already a child of `$parent`
     */
    public function hasChild(Item $parent, Item $child): bool
    {
        return array_key_exists($child->getName(), $this->rolesStorage->getChildrenByName($parent->getName()));
    }

    /**
     * Assigns a role or permission to a user.
     *
     * @param Item $item
     * @param string $userId The user ID.
     *
     * @throws \Exception If the role has already been assigned to the user.
     *
     * @return Assignment|null The role or permission assignment information.
     */
    public function assign(Item $item, string $userId): ?Assignment
    {
        if (!$this->hasItem($item->getName())) {
            throw new InvalidArgumentException(sprintf('Unknown %s "%s".', $item->getType(), $item->getName()));
        }

        if ($this->assignmentsStorage->getUserAssignmentByName($userId, $item->getName()) !== null) {
            throw new InvalidArgumentException(
                sprintf('"%s" %s has already been assigned to user %s.', $item->getName(), $item->getType(), $userId)
            );
        }

        $this->assignmentsStorage->addAssignment($userId, $item);

        return $this->assignmentsStorage->getUserAssignmentByName($userId, $item->getName());
    }

    /**
     * Revokes a role or a permission from a user.
     *
     * @param Item $role
     * @param string $userId The user ID.
     */
    public function revoke(Item $role, string $userId): void
    {
        if ($this->assignmentsStorage->getUserAssignmentByName($userId, $role->getName()) !== null) {
            $this->assignmentsStorage->removeAssignment($userId, $role);
        }
    }

    /**
     * Revokes all roles and permissions from a user.
     *
     * @param string $userId The user ID.
     */
    public function revokeAll(string $userId): void
    {
        $this->assignmentsStorage->removeAllAssignments($userId);
    }

    /**
     * Returns the roles that are assigned to the user via {@see assign()}.
     * Note that child roles that are not assigned directly to the user will not be returned.
     *
     * @param string $userId The user ID.
     *
     * @return Role[] All roles directly assigned to the user. The array is indexed by the role names.
     */
    public function getRolesByUser(string $userId): array
    {
        $roles = $this->getDefaultRoleInstances();
        foreach ($this->assignmentsStorage->getUserAssignments($userId) as $name => $assignment) {
            $role = $this->rolesStorage->getRoleByName($assignment->getItemName());
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
     * @throws InvalidArgumentException If Role was not found that are getting by $roleName
     *
     * @return Role[] Child roles. The array is indexed by the role names.
     * First element is an instance of the parent Role itself.
     */
    public function getChildRoles(string $roleName): array
    {
        $role = $this->rolesStorage->getRoleByName($roleName);
        if ($role === null) {
            throw new InvalidArgumentException(sprintf('Role "%s" not found.', $roleName));
        }

        $result = [];
        $this->getChildrenRecursive($roleName, $result);

        return array_merge([$roleName => $role], $this->getRolesPresentInArray($result));
    }

    /**
     * Returns all permissions that the specified role represents.
     *
     * @param string $roleName The role name.
     *
     * @return Permission[] All permissions that the role represents. The array is indexed by the permission names.
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
     * @param string $userId The user ID.
     *
     * @return Permission[] All permissions that the user has. The array is indexed by the permission names.
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
     * @return array Array of user ID strings.
     */
    public function getUserIdsByRole(string $roleName): array
    {
        $result = [];
        $roles = [$roleName];
        $this->getParentRolesRecursive($roleName, $roles);

        /**
         * @var Assignment[] $assignments
         */
        foreach ($this->assignmentsStorage->getAssignments() as $userId => $assignments) {
            foreach ($assignments as $userAssignment) {
                if (in_array($userAssignment->getItemName(), $roles, true)) {
                    $result[] = $userId;
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
     * @param Role $role
     */
    public function removeRole(Role $role): void
    {
        $this->removeItem($role);
    }

    /**
     * @param string $name
     * @param Role $role
     */
    public function updateRole(string $name, Role $role): void
    {
        $this->checkItemNameForUpdate($role, $name);
        $this->createItemRuleIfNotExist($role);
        $this->rolesStorage->updateItem($name, $role);
        $this->assignmentsStorage->updateAssignmentsForItemName($name, $role);
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
     * @param Permission $permission
     */
    public function removePermission(Permission $permission): void
    {
        $this->removeItem($permission);
    }

    /**
     * @param string $name
     * @param Permission $permission
     */
    public function updatePermission(string $name, Permission $permission): void
    {
        $this->checkItemNameForUpdate($permission, $name);
        $this->createItemRuleIfNotExist($permission);
        $this->rolesStorage->updateItem($name, $permission);
        $this->assignmentsStorage->updateAssignmentsForItemName($name, $permission);
    }

    /**
     * @param Rule $rule
     */
    public function addRule(Rule $rule): void
    {
        $this->rolesStorage->addRule($rule);
    }

    /**
     * @param Rule $rule
     */
    public function removeRule(Rule $rule): void
    {
        if ($this->rolesStorage->getRuleByName($rule->getName()) !== null) {
            $this->rolesStorage->removeRule($rule->getName());
        }
    }

    /**
     * @param string $name
     * @param Rule $rule
     */
    public function updateRule(string $name, Rule $rule): void
    {
        if ($rule->getName() !== $name) {
            $this->rolesStorage->removeRule($name);
        }
        $this->rolesStorage->addRule($rule);
    }

    /**
     * Set default roles.
     *
     * @param \Closure|string[] $roles either array of roles or a closure returning it
     *
     * @throws InvalidArgumentException When $roles is neither array nor closure.
     * @throws RuntimeException When callable returns non array.
     *
     * @return $this
     */
    public function setDefaultRoles($roles): self
    {
        if (is_array($roles)) {
            $this->defaultRoles = $roles;
            return $this;
        }

        /** @psalm-suppress RedundantConditionGivenDocblockType */
        if ($roles instanceof \Closure) {
            $roles = $roles();
            if (!is_array($roles)) {
                throw new RuntimeException('Default roles closure must return an array.');
            }
            $this->defaultRoles = $roles;
            return $this;
        }

        throw new InvalidArgumentException('Default roles must be either an array or a closure.');
    }

    /**
     * Get default roles.
     *
     * @return string[] Default roles.
     */
    public function getDefaultRoles(): array
    {
        return $this->defaultRoles;
    }

    /**
     * Returns defaultRoles as array of Role objects.
     *
     * @return Role[] Default roles. The array is indexed by the role names.
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
     * return the value of {@see Rule::execute()()}.
     *
     * @param string $user The user ID. This should be a string representing
     * the unique identifier of a user.
     * @param Item $item The auth item that needs to execute its rule.
     * @param array $params Parameters passed to {@see AccessCheckerInterface::userHasPermission()} and will be passed
     * to the rule.
     *
     * @throws RuntimeException if the auth item has an invalid rule.
     *
     * @return bool the return value of {@see Rule::execute()}. If the auth item does not specify a rule, true will be
     * returned.
     */
    private function executeRule(string $user, Item $item, array $params): bool
    {
        if ($item->getRuleName() === null) {
            return true;
        }
        /** @psalm-suppress PossiblyNullArgument */
        $rule = $this->rolesStorage->getRuleByName($item->getRuleName());
        if ($rule === null) {
            /** @psalm-suppress PossiblyNullArgument */
            throw new RuntimeException(sprintf('Rule not found: %s.', $item->getRuleName()));
        }

        return $rule->execute($user, $item, $params);
    }

    private function createItemRuleIfNotExist(Item $item): void
    {
        /** @psalm-suppress PossiblyNullArgument */
        if ($item->getRuleName() !== null && $this->rolesStorage->getRuleByName($item->getRuleName()) === null) {
            $rule = $this->createRule($item->getRuleName());
            $this->addRule($rule);
        }
    }

    private function addItem(Item $item): void
    {
        $time = time();
        if (!$item->hasCreatedAt()) {
            $item = $item->withCreatedAt($time);
        }
        if (!$item->hasUpdatedAt()) {
            $item = $item->withUpdatedAt($time);
        }

        $this->rolesStorage->addItem($item);
    }

    /** @psalm-param class-string<Rule> $name */
    private function createRule(string $name): Rule
    {
        return $this->ruleFactory->create($name);
    }

    private function getParentRolesRecursive(string $roleName, array &$result): void
    {
        /**
         * @var Item[] $items
         */
        foreach ($this->rolesStorage->getChildren() as $parentRole => $items) {
            foreach ($items as $item) {
                if ($item->getName() === $roleName) {
                    $result[] = $parentRole;
                    $this->getParentRolesRecursive($parentRole, $result);
                    break;
                }
            }
        }
    }

    private function hasItem(string $name): bool
    {
        return $this->rolesStorage->getItemByName($name) !== null;
    }

    private function normalizePermissions(array $permissions): array
    {
        $normalizePermissions = [];
        foreach (array_keys($permissions) as $itemName) {
            $permission = $this->rolesStorage->getPermissionByName($itemName);
            if ($permission !== null) {
                $normalizePermissions[$itemName] = $permission;
            }
        }

        return $normalizePermissions;
    }

    /**
     * Returns all permissions that are directly assigned to user.
     *
     * @param string $userId The user ID.
     *
     * @return Permission[] All direct permissions that the user has. The array is indexed by the permission names.
     */
    private function getDirectPermissionsByUser(string $userId): array
    {
        $permissions = [];
        foreach ($this->assignmentsStorage->getUserAssignments($userId) as $name => $assignment) {
            $permission = $this->rolesStorage->getPermissionByName($assignment->getItemName());
            if ($permission !== null) {
                $permissions[$name] = $permission;
            }
        }

        return $permissions;
    }

    /**
     * Returns all permissions that the user inherits from the roles assigned to him.
     *
     * @param string $userId The user ID.
     *
     * @return Permission[] All inherited permissions that the user has. The array is indexed by the permission names.
     */
    private function getInheritedPermissionsByUser(string $userId): array
    {
        $assignments = $this->assignmentsStorage->getUserAssignments($userId);
        $result = [];
        foreach (array_keys($assignments) as $roleName) {
            $this->getChildrenRecursive($roleName, $result);
        }

        if (empty($result)) {
            return [];
        }

        return $this->normalizePermissions($result);
    }

    private function removeItem(Item $item): void
    {
        if ($this->hasItem($item->getName())) {
            $this->rolesStorage->removeItem($item);
        }
    }

    /**
     * Performs access check for the specified user.
     *
     * @param string $user The user ID. This should br a string representing the unique identifier of a user.
     * @param string $itemName The name of the permission or role that need access check.
     * @param array $params Name-value pairs that would be passed to rules associated
     * with the permissions and roles assigned to the user. A param with name 'user' is
     * added to this array, which holds the value of `$userId`.
     * @param Assignment[] $assignments The assignments to the specified user.
     *
     * @throws RuntimeException
     *
     * @return bool Whether the operations can be performed by the user.
     */
    private function userHasPermissionRecursive(
        string $user,
        string $itemName,
        array $params,
        array $assignments
    ): bool {
        $item = $this->rolesStorage->getItemByName($itemName);
        if ($item === null) {
            return false;
        }

        if (!$this->executeRule($user, $item, $params)) {
            return false;
        }

        if (isset($assignments[$itemName])) {
            return true;
        }

        foreach ($this->rolesStorage->getChildren() as $parentName => $children) {
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
     * @param Item $parent Parent item.
     * @param Item $child The child item that is to be added to the hierarchy.
     *
     * @return bool Whether a loop exists.
     */
    private function detectLoop(Item $parent, Item $child): bool
    {
        if ($child->getName() === $parent->getName()) {
            return true;
        }

        $children = $this->rolesStorage->getChildrenByName($child->getName());
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
     * @param string $name The name of the item whose children are to be looked for.
     * @param array $result The children and grand children (in array keys).
     */
    private function getChildrenRecursive(string $name, array &$result): void
    {
        $children = $this->rolesStorage->getChildrenByName($name);
        if (empty($children)) {
            return;
        }

        foreach ($children as $childName => $child) {
            $result[$childName] = true;
            $this->getChildrenRecursive($childName, $result);
        }
    }

    private function getRolesPresentInArray(array $array): array
    {
        return array_filter(
            $this->rolesStorage->getRoles(),
            static function (Role $roleItem) use ($array) {
                return array_key_exists($roleItem->getName(), $array);
            }
        );
    }

    private function canBeParent(Item $parent, Item $child): bool
    {
        return $parent->getType() !== Item::TYPE_PERMISSION || $child->getType() !== Item::TYPE_ROLE;
    }

    private function checkItemNameForUpdate(Item $item, string $name): void
    {
        if ($item->getName() === $name || !$this->hasItem($item->getName())) {
            return;
        }

        throw new InvalidArgumentException(
            sprintf(
                'Unable to change the item name. The name "%s" is already used by another item.',
                $item->getName()
            )
        );
    }
}
