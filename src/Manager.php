<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

use Closure;
use Exception;
use InvalidArgumentException;
use RuntimeException;
use Yiisoft\Access\AccessCheckerInterface;
use Yiisoft\Rbac\Exception\DefaultRoleNotFoundException;
use Yiisoft\Rbac\Exception\ItemAlreadyExistsException;

use function array_key_exists;
use function get_class;
use function gettype;
use function in_array;
use function is_array;
use function is_int;
use function is_object;
use function is_string;

/**
 * An authorization manager that helps with building RBAC hierarchy and check for permissions.
 */
final class Manager implements AccessCheckerInterface
{
    private ItemsStorageInterface $itemsStorage;
    private AssignmentsStorageInterface $assignmentsStorage;
    private RuleFactoryInterface $ruleFactory;

    /**
     * @var string[] A list of role names that are assigned to every user automatically without calling {@see assign()}.
     * Note that these roles are applied to users, regardless of their state of authentication.
     */
    private array $defaultRoleNames = [];

    /**
     * @var bool Whether to enable assigning permissions directly to user. Prefer assigning roles only.
     */
    private bool $enableDirectPermissions;

    private ?string $guestRoleName = null;

    /**
     * @param ItemsStorageInterface $itemsStorage Items storage.
     * @param AssignmentsStorageInterface $assignmentsStorage Assignments storage.
     * @param RuleFactoryInterface $ruleFactory Rule factory.
     * @param bool $enableDirectPermissions Whether to enable assigning permissions directly to user. Prefer assigning
     * roles only.
     */
    public function __construct(
        ItemsStorageInterface $itemsStorage,
        AssignmentsStorageInterface $assignmentsStorage,
        RuleFactoryInterface $ruleFactory,
        bool $enableDirectPermissions = false
    ) {
        $this->itemsStorage = $itemsStorage;
        $this->assignmentsStorage = $assignmentsStorage;
        $this->ruleFactory = $ruleFactory;
        $this->enableDirectPermissions = $enableDirectPermissions;
    }

    /**
     * @inheritdoc
     */
    public function userHasPermission($userId, string $permissionName, array $parameters = []): bool
    {
        if ($userId === null) {
            return $this->guestHasPermission($permissionName);
        }

        $userId = $this->ensureStringUserId($userId);
        $assignments = $this->assignmentsStorage->getByUserId($userId);

        if (empty($assignments)) {
            return false;
        }

        return $this->userHasItem(
            $userId,
            $this->itemsStorage->getPermission($permissionName),
            $parameters,
            $assignments
        );
    }

    /**
     * Checks the possibility of adding a child to parent.
     *
     * @param string $parentName The name of the parent item.
     * @param string $childName The name of the child item to be added to the hierarchy.
     *
     * @return bool Whether it is possible to add the child to the parent.
     */
    public function canAddChild(string $parentName, string $childName): bool
    {
        return $this->canBeParent($parentName, $childName) && !$this->hasLoop($parentName, $childName);
    }

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
    public function addChild(string $parentName, string $childName): self
    {
        if (!$this->hasItem($parentName)) {
            throw new InvalidArgumentException(
                sprintf('Either "%s" does not exist.', $parentName)
            );
        }

        if (!$this->hasItem($childName)) {
            throw new InvalidArgumentException(
                sprintf('Either "%s" does not exist.', $childName)
            );
        }

        if ($parentName === $childName) {
            throw new InvalidArgumentException(sprintf('Cannot add "%s" as a child of itself.', $parentName));
        }

        if (!$this->canBeParent($parentName, $childName)) {
            throw new InvalidArgumentException(
                sprintf('Can not add "%s" role as a child of "%s" permission.', $childName, $parentName)
            );
        }

        if ($this->hasLoop($parentName, $childName)) {
            throw new RuntimeException(
                sprintf(
                    'Cannot add "%s" as a child of "%s". A loop has been detected.',
                    $childName,
                    $parentName
                )
            );
        }

        if (isset($this->itemsStorage->getChildren($parentName)[$childName])) {
            throw new RuntimeException(
                sprintf('The item "%s" already has a child "%s".', $parentName, $childName)
            );
        }

        $this->itemsStorage->addChild($parentName, $childName);

        return $this;
    }

    /**
     * Removes a child from its parent.
     * Note, the child item is not deleted. Only the parent-child relationship is removed.
     *
     * @param string $parentName The name of the parent item.
     * @param string $childName The name of the child item.
     *
     * @return self
     */
    public function removeChild(string $parentName, string $childName): self
    {
        if ($this->hasChild($parentName, $childName)) {
            $this->itemsStorage->removeChild($parentName, $childName);
        }

        return $this;
    }

    /**
     * Removes all children form their parent.
     * Note, the children items are not deleted. Only the parent-child relationships are removed.
     *
     * @param string $parentName The name of the parent item.
     *
     * @return self
     */
    public function removeChildren(string $parentName): self
    {
        if ($this->itemsStorage->hasChildren($parentName)) {
            $this->itemsStorage->removeChildren($parentName);
        }

        return $this;
    }

    /**
     * Returns a value indicating whether the child already exists for the parent.
     *
     * @param string $parentName The name of the parent item.
     * @param string $childName The name of the child item.
     *
     * @return bool Whether `$child` is already a child of `$parent`
     */
    public function hasChild(string $parentName, string $childName): bool
    {
        return array_key_exists($childName, $this->itemsStorage->getChildren($parentName));
    }

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
    public function assign(string $itemName, $userId): self
    {
        $userId = $this->ensureStringUserId($userId);

        $item = $this->itemsStorage->get($itemName);

        if ($item === null) {
            throw new InvalidArgumentException("There is no item named \"$itemName\".");
        }

        if (!$this->enableDirectPermissions && $item->getType() === Item::TYPE_PERMISSION) {
            throw new InvalidArgumentException(
                'Assigning permissions directly is disabled. Prefer assigning roles only.'
            );
        }

        if ($this->assignmentsStorage->get($itemName, $userId) !== null) {
            throw new InvalidArgumentException(
                sprintf('"%s" %s has already been assigned to user %s.', $itemName, $item->getType(), $userId)
            );
        }

        $this->assignmentsStorage->add($itemName, $userId);

        return $this;
    }

    /**
     * Revokes a role or a permission from a user.
     *
     * @param string $itemName The name of the role or permission to be revoked.
     * @param int|object|string $userId The user ID.
     *
     * @return self
     */
    public function revoke(string $itemName, $userId): self
    {
        $userId = $this->ensureStringUserId($userId);

        if ($this->assignmentsStorage->get($itemName, $userId) !== null) {
            $this->assignmentsStorage->remove($itemName, $userId);
        }

        return $this;
    }

    /**
     * Revokes all roles and permissions from a user.
     *
     * @param int|object|string $userId The user ID.
     *
     * @return self
     */
    public function revokeAll($userId): self
    {
        $userId = $this->ensureStringUserId($userId);

        $this->assignmentsStorage->removeByUserId($userId);

        return $this;
    }

    /**
     * Returns the roles that are assigned to the user via {@see assign()}.
     * Note that child roles that are not assigned directly to the user will not be returned.
     *
     * @param int|object|string $userId The user ID.
     *
     * @return Role[] All roles directly assigned to the user. The array is indexed by the role names.
     */
    public function getRolesByUserId($userId): array
    {
        $userId = $this->ensureStringUserId($userId);

        $roles = $this->getDefaultRoles();
        foreach ($this->assignmentsStorage->getByUserId($userId) as $name => $assignment) {
            $role = $this->itemsStorage->getRole($assignment->getItemName());
            if ($role !== null) {
                $roles[$name] = $role;
            }
        }

        return $roles;
    }

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
    public function getChildRoles(string $roleName): array
    {
        $role = $this->itemsStorage->getRole($roleName);
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
     *
     * @psalm-return array<string,Permission>
     */
    public function getPermissionsByRoleName(string $roleName): array
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
     * @param int|object|string $userId The user ID.
     *
     * @return Permission[] All permissions that the user has. The array is indexed by the permission names.
     */
    public function getPermissionsByUserId($userId): array
    {
        $userId = $this->ensureStringUserId($userId);

        return array_merge(
            $this->getDirectPermissionsByUser($userId),
            $this->getInheritedPermissionsByUser($userId)
        );
    }

    /**
     * @param mixed $userId
     *
     * @return string
     */
    private function ensureStringUserId($userId): string
    {
        if (!is_string($userId) && !is_int($userId) && !(is_object($userId) && method_exists($userId, '__toString'))) {
            $type = is_object($userId) ? get_class($userId) : gettype($userId);
            throw new InvalidArgumentException(
                sprintf(
                    'User ID must be a string, an integer, or an object with method "__toString()", %s given.',
                    $type
                )
            );
        }
        return (string) $userId;
    }

    /**
     * Returns all user IDs assigned to the role specified.
     *
     * @param string $roleName The role name.
     *
     * @return array Array of user ID strings.
     */
    public function getUserIdsByRoleName(string $roleName): array
    {
        $result = [];
        $roles = [$roleName, ...array_keys($this->itemsStorage->getParents($roleName))];

        foreach ($this->assignmentsStorage->getAll() as $userId => $assignments) {
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
     *
     * @throws ItemAlreadyExistsException
     *
     * @return self
     */
    public function addRole(Role $role): self
    {
        $this->addItem($role);
        return $this;
    }

    /**
     * @param string $name The role name.
     *
     * @return self
     */
    public function removeRole(string $name): self
    {
        $this->removeItem($name);
        return $this;
    }

    /**
     * @param string $name The role name.
     * @param Role $role
     *
     * @return self
     */
    public function updateRole(string $name, Role $role): self
    {
        $this->checkItemNameForUpdate($role, $name);

        $this->itemsStorage->update($name, $role);
        $this->assignmentsStorage->renameItem($name, $role->getName());

        return $this;
    }

    /**
     * @param Permission $permission
     *
     * @throws ItemAlreadyExistsException
     *
     * @return self
     */
    public function addPermission(Permission $permission): self
    {
        $this->addItem($permission);
        return $this;
    }

    /**
     * @param string $permissionName The permission name.
     *
     * @return self
     */
    public function removePermission(string $permissionName): self
    {
        $this->removeItem($permissionName);
        return $this;
    }

    /**
     * @param string $name The permission name.
     * @param Permission $permission
     *
     * @return self
     */
    public function updatePermission(string $name, Permission $permission): self
    {
        $this->checkItemNameForUpdate($permission, $name);

        $this->itemsStorage->update($name, $permission);
        $this->assignmentsStorage->renameItem($name, $permission->getName());

        return $this;
    }

    /**
     * Set default role names.
     *
     * @param Closure|string[] $roleNames Either array of role names or a closure returning it.
     *
     * @throws InvalidArgumentException When `$roles` is neither array nor closure.
     * @throws RuntimeException When callable returns not array.
     */
    public function setDefaultRoleNames($roleNames): self
    {
        if (is_array($roleNames)) {
            $this->defaultRoleNames = $roleNames;
            return $this;
        }

        /** @psalm-suppress RedundantConditionGivenDocblockType */
        if ($roleNames instanceof Closure) {
            $defaultRoleNames = $roleNames();
            if (!is_array($defaultRoleNames)) {
                throw new RuntimeException('Default role names closure must return an array.');
            }
            /** @var string[] $defaultRoleNames */
            $this->defaultRoleNames = $defaultRoleNames;
            return $this;
        }

        throw new InvalidArgumentException('Default role names must be either an array or a closure.');
    }

    /**
     * Returns default role names.
     *
     * @return string[] Default role names.
     */
    public function getDefaultRoleNames(): array
    {
        return $this->defaultRoleNames;
    }

    /**
     * Returns default roles.
     *
     * @return Role[] Default roles. The array is indexed by the role names.
     */
    public function getDefaultRoles(): array
    {
        $roles = [];
        foreach ($this->defaultRoleNames as $roleName) {
            $role = $this->itemsStorage->getRole($roleName);
            if ($role === null) {
                throw new DefaultRoleNotFoundException("Default role \"$roleName\" not found.");
            }
            $roles[$roleName] = $role;
        }

        return $roles;
    }

    /**
     * Set guest role name.
     *
     * @param string|null $name The guest role name.
     */
    public function setGuestRoleName(?string $name): self
    {
        $this->guestRoleName = $name;
        return $this;
    }

    /**
     * Executes the rule associated with the specified role or permission.
     *
     * If the item does not specify a rule, this method will return `true`. Otherwise, it will
     * return the value of {@see RuleInterface::execute()}.
     *
     * @param string $user The user ID. This should be a string representing the unique identifier of a user.
     * @param Item $item The role or the permission that needs to execute its rule.
     * @param array $params Parameters passed to {@see AccessCheckerInterface::userHasPermission()} and will be passed
     * to the rule.
     *
     * @throws RuntimeException If the role or the permission has an invalid rule.
     *
     * @return bool The return value of {@see RuleInterface::execute()}. If the role or the permission does not specify
     * a rule, `true` will be returned.
     */
    private function executeRule(string $user, Item $item, array $params): bool
    {
        if ($item->getRuleName() === null) {
            return true;
        }

        return $this->ruleFactory
            ->create($item->getRuleName())
            ->execute($user, $item, $params);
    }

    /**
     * @throws ItemAlreadyExistsException
     */
    private function addItem(Item $item): void
    {
        if ($this->itemsStorage->exists($item->getName())) {
            throw new ItemAlreadyExistsException($item);
        }

        $time = time();
        if (!$item->hasCreatedAt()) {
            $item = $item->withCreatedAt($time);
        }
        if (!$item->hasUpdatedAt()) {
            $item = $item->withUpdatedAt($time);
        }

        $this->itemsStorage->add($item);
    }

    private function hasItem(string $name): bool
    {
        return $this->itemsStorage->get($name) !== null;
    }

    /**
     * @param array<string,mixed> $permissionNames
     *
     * @return Permission[]
     *
     * @psalm-return array<string,Permission>
     */
    private function normalizePermissions(array $permissionNames): array
    {
        $normalizePermissions = [];
        foreach (array_keys($permissionNames) as $permissionName) {
            $permission = $this->itemsStorage->getPermission($permissionName);
            if ($permission !== null) {
                $normalizePermissions[$permissionName] = $permission;
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
     *
     * @psalm-return array<string,Permission>
     */
    private function getDirectPermissionsByUser(string $userId): array
    {
        $permissions = [];
        foreach ($this->assignmentsStorage->getByUserId($userId) as $name => $assignment) {
            $permission = $this->itemsStorage->getPermission($assignment->getItemName());
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
        $assignments = $this->assignmentsStorage->getByUserId($userId);
        $result = [];
        foreach (array_keys($assignments) as $roleName) {
            $this->getChildrenRecursive($roleName, $result);
        }

        if (empty($result)) {
            return [];
        }

        return $this->normalizePermissions($result);
    }

    private function removeItem(string $name): void
    {
        if ($this->hasItem($name)) {
            $this->itemsStorage->remove($name);
            $this->assignmentsStorage->removeByItemName($name);
        }
    }

    /**
     * Performs access check for the specified user.
     *
     * @param string $user The user ID. This should be a string representing the unique identifier of a user.
     * @param Item|null $item The permission or the role that need access check.
     * @param array $params Name-value pairs that would be passed to rules associated with the permissions and roles
     * assigned to the user. A param with name 'user' is added to this array, which holds the value of `$userId`.
     * @param Assignment[] $assignments The assignments to the specified user.
     *
     * @throws RuntimeException
     *
     * @return bool Whether the operations can be performed by the user.
     */
    private function userHasItem(
        string $user,
        ?Item $item,
        array $params,
        array $assignments
    ): bool {
        if ($item === null) {
            return false;
        }

        if (!$this->executeRule($user, $item, $params)) {
            return false;
        }

        if (array_key_exists($item->getName(), $assignments)) {
            return true;
        }

        foreach ($this->itemsStorage->getParents($item->getName()) as $parentName => $_parent) {
            if (array_key_exists($parentName, $assignments)) {
                return true;
            }
        }

        return false;
    }

    private function guestHasPermission(string $permissionName): bool
    {
        if ($this->guestRoleName === null) {
            return false;
        }

        if (
            $this->itemsStorage->getRole($this->guestRoleName) === null
            || !$this->itemsStorage->hasChildren($this->guestRoleName)
        ) {
            return false;
        }
        $permissions = $this->itemsStorage->getChildren($this->guestRoleName);

        return isset($permissions[$permissionName]);
    }

    /**
     * Checks whether there is a loop in the authorization item hierarchy.
     *
     * @param string $parentName Name of the parent item.
     * @param string $childName Name of the child item that is to be added to the hierarchy.
     *
     * @return bool Whether a loop exists.
     */
    private function hasLoop(string $parentName, string $childName): bool
    {
        if ($childName === $parentName) {
            return true;
        }

        $children = $this->itemsStorage->getChildren($childName);
        if (empty($children)) {
            return false;
        }

        foreach ($children as $groupChild) {
            if ($this->hasLoop($parentName, $groupChild->getName())) {
                return true;
            }
        }

        return false;
    }

    /**
     * Recursively finds all children and grand children of the specified item.
     *
     * @param string $name The name of the item whose children are to be looked for.
     * @param true[] $result The children and grand children (in array keys).
     *
     * @psalm-param array<string,true> $result
     */
    private function getChildrenRecursive(string $name, array &$result): void
    {
        $children = $this->itemsStorage->getChildren($name);
        if (empty($children)) {
            return;
        }

        foreach ($children as $childName => $_child) {
            $result[$childName] = true;
            $this->getChildrenRecursive($childName, $result);
        }
    }

    /**
     * @param true[] $array
     *
     * @psalm-param array<string,true> $array
     *
     * @return Role[]
     */
    private function getRolesPresentInArray(array $array): array
    {
        return array_filter(
            $this->itemsStorage->getRoles(),
            static function (Role $roleItem) use ($array) {
                return array_key_exists($roleItem->getName(), $array);
            }
        );
    }

    private function canBeParent(string $parentName, string $childName): bool
    {
        $parent = $this->itemsStorage->get($parentName);
        if ($parent === null) {
            throw new InvalidArgumentException("There is no item named \"$parentName\".");
        }

        $child = $this->itemsStorage->get($childName);
        if ($child === null) {
            throw new InvalidArgumentException("There is no item named \"$childName\".");
        }

        return $parent->getType() !== Item::TYPE_PERMISSION || $child->getType() !== Item::TYPE_ROLE;
    }

    private function checkItemNameForUpdate(Item $item, string $name): void
    {
        if ($item->getName() === $name || !$this->hasItem($item->getName())) {
            return;
        }

        throw new InvalidArgumentException(
            sprintf(
                'Unable to change the role or the permission name. ' .
                'The name "%s" is already used by another role or permission.',
                $item->getName()
            )
        );
    }
}
