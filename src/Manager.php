<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

use Closure;
use InvalidArgumentException;
use RuntimeException;
use Stringable;
use Yiisoft\Access\AccessCheckerInterface;
use Yiisoft\Rbac\Exception\DefaultRolesNotFoundException;
use Yiisoft\Rbac\Exception\ItemAlreadyExistsException;

use function is_array;

/**
 * Helps to manage RBAC hierarchy and check for permissions.
 */
final class Manager implements ManagerInterface
{
    /**
     * @var string[] A list of role names that are assigned to every user automatically without calling {@see assign()}.
     * Note that these roles are applied to users, regardless of their state of authentication.
     */
    private array $defaultRoleNames = [];
    private ?string $guestRoleName = null;

    /**
     * @param ItemsStorageInterface $itemsStorage Items storage.
     * @param AssignmentsStorageInterface $assignmentsStorage Assignments storage.
     * @param RuleFactoryInterface $ruleFactory Rule factory.
     * @param bool $enableDirectPermissions Whether to enable assigning permissions directly to user. Prefer assigning
     * roles only.
     */
    public function __construct(
        private ItemsStorageInterface $itemsStorage,
        private AssignmentsStorageInterface $assignmentsStorage,
        private RuleFactoryInterface $ruleFactory,
        private bool $enableDirectPermissions = false,
    ) {
    }

    public function userHasPermission(
        int|string|Stringable|null $userId,
        string $permissionName,
        array $parameters = [],
    ): bool {
        $permission = $this->itemsStorage->getPermission($permissionName);
        if ($permission === null) {
            return false;
        }

        $items = array_merge(
            [$permission->getName() => $permission],
            $this->itemsStorage->getParents($permission->getName()),
        );

        if ($userId !== null) {
            $userId = (string) $userId;
            $userItemNames = $this->assignmentsStorage->filterUserItemNames($userId, array_keys($items));

            $userItems = [];
            foreach ($userItemNames as $itemName) {
                $userItems[$itemName] = $items[$itemName];
            }

            foreach ($userItems as $userItem) {
                foreach ($this->itemsStorage->getAllChildren($userItem->getName()) as $childItem) {
                    if (array_key_exists($childItem->getName(), $items)) {
                        $userItems[$childItem->getName()] = $childItem;
                    }
                }
            }
        } else {
            if ($this->guestRoleName === null) {
                return false;
            }

            if (!$this->itemsStorage->roleExists($this->guestRoleName)) {
                return false;
            }

            $guestChildren = $this->itemsStorage->getAllChildren($this->guestRoleName);

            $userItems = [];
            foreach ($items as $itemName => $_item) {
                if (array_key_exists($itemName, $guestChildren)) {
                    $userItems[$itemName] = $items[$itemName];
                }
            }
        }

        if (empty($userItems)) {
            return false;
        }

        foreach ($userItems as $item) {
            if (!$this->executeRule($userId, $item, $parameters)) {
                return false;
            }
        }

        return true;
    }

    public function canAddChild(string $parentName, string $childName): bool
    {
        try {
            $this->assertFutureChild($parentName, $childName);
        } catch (RuntimeException) {
            return false;
        }

        return true;
    }

    public function addChild(string $parentName, string $childName): self
    {
        $this->assertFutureChild($parentName, $childName);
        $this->itemsStorage->addChild($parentName, $childName);

        return $this;
    }

    public function removeChild(string $parentName, string $childName): self
    {
        $this->itemsStorage->removeChild($parentName, $childName);

        return $this;
    }

    public function removeChildren(string $parentName): self
    {
        $this->itemsStorage->removeChildren($parentName);

        return $this;
    }

    public function hasChild(string $parentName, string $childName): bool
    {
        return $this->itemsStorage->hasDirectChild($parentName, $childName);
    }

    public function hasChildren(string $parentName): bool
    {
        return $this->itemsStorage->hasChildren($parentName);
    }

    public function assign(string $itemName, int|Stringable|string $userId, ?int $createdAt = null): self
    {
        $userId = (string) $userId;

        $item = $this->itemsStorage->get($itemName);
        if ($item === null) {
            throw new InvalidArgumentException("There is no item named \"$itemName\".");
        }

        if (!$this->enableDirectPermissions && $item->getType() === Item::TYPE_PERMISSION) {
            throw new InvalidArgumentException(
                'Assigning permissions directly is disabled. Prefer assigning roles only.'
            );
        }

        if ($this->assignmentsStorage->exists($itemName, $userId)) {
            throw new InvalidArgumentException(
                "\"$itemName\" {$item->getType()} has already been assigned to user $userId.",
            );
        }

        $assignment = new Assignment($userId, $itemName, $createdAt ?? time());
        $this->assignmentsStorage->add($assignment);

        return $this;
    }

    public function revoke(string $itemName, int|Stringable|string $userId): self
    {
        $this->assignmentsStorage->remove($itemName, (string) $userId);

        return $this;
    }

    public function revokeAll(int|Stringable|string $userId): self
    {
        $this->assignmentsStorage->removeByUserId((string) $userId);

        return $this;
    }

    public function getItemsByUserId(int|Stringable|string $userId): array
    {
        $userId = (string) $userId;
        $assignments = $this->assignmentsStorage->getByUserId($userId);
        $items = array_merge(
            $this->getDefaultRoles(),
            $this->itemsStorage->getByNames(array_keys($assignments)),
        );

        foreach ($assignments as $assignment) {
            $items = array_merge($items, $this->itemsStorage->getAllChildren($assignment->getItemName()));
        }

        return $items;
    }

    public function getRolesByUserId(int|Stringable|string $userId): array
    {
        $userId = (string) $userId;
        $assignments = $this->assignmentsStorage->getByUserId($userId);
        $roles = array_merge(
            $this->getDefaultRoles(),
            $this->itemsStorage->getRolesByNames(array_keys($assignments)),
        );

        foreach ($assignments as $assignment) {
            $roles = array_merge($roles, $this->itemsStorage->getAllChildRoles($assignment->getItemName()));
        }

        return $roles;
    }

    public function getChildRoles(string $roleName): array
    {
        if (!$this->itemsStorage->roleExists($roleName)) {
            throw new InvalidArgumentException("Role \"$roleName\" not found.");
        }

        return $this->itemsStorage->getAllChildRoles($roleName);
    }

    public function getPermissionsByRoleName(string $roleName): array
    {
        return $this->itemsStorage->getAllChildPermissions($roleName);
    }

    public function getPermissionsByUserId(int|Stringable|string $userId): array
    {
        $userId = (string) $userId;
        $assignments = $this->assignmentsStorage->getByUserId($userId);
        $permissions = $this->itemsStorage->getPermissionsByNames(array_keys($assignments));

        foreach ($assignments as $assignment) {
            $permissions = array_merge(
                $permissions,
                $this->itemsStorage->getAllChildPermissions($assignment->getItemName()),
            );
        }

        return $permissions;
    }

    public function getUserIdsByRoleName(string $roleName): array
    {
        $roleNames = [$roleName, ...array_keys($this->itemsStorage->getParents($roleName))];

        return array_map(
            static fn(Assignment $assignment): string => $assignment->getUserId(),
            $this->assignmentsStorage->getByItemNames($roleNames),
        );
    }

    public function addRole(Role $role): self
    {
        $this->addItem($role);
        return $this;
    }

    public function getRole(string $name): ?Role
    {
        return $this->itemsStorage->getRole($name);
    }

    public function updateRole(string $name, Role $role): self
    {
        $this->assertItemNameForUpdate($role, $name);

        $this->itemsStorage->update($name, $role);
        $this->assignmentsStorage->renameItem($name, $role->getName());

        return $this;
    }

    public function removeRole(string $name): self
    {
        $this->removeItem($name);
        return $this;
    }

    public function addPermission(Permission $permission): self
    {
        $this->addItem($permission);
        return $this;
    }

    public function getPermission(string $name): ?Permission
    {
        return $this->itemsStorage->getPermission($name);
    }

    public function updatePermission(string $name, Permission $permission): self
    {
        $this->assertItemNameForUpdate($permission, $name);

        $this->itemsStorage->update($name, $permission);
        $this->assignmentsStorage->renameItem($name, $permission->getName());

        return $this;
    }

    public function removePermission(string $name): self
    {
        $this->removeItem($name);
        return $this;
    }

    public function setDefaultRoleNames(array|Closure $roleNames): self
    {
        $roleNames = $this->getDefaultRoleNamesForUpdate($roleNames);
        if (!empty($roleNames)) {
            $roleNames = array_keys($this->filterStoredRoles($roleNames));
        }

        $this->defaultRoleNames = $roleNames;

        return $this;
    }

    public function getDefaultRoleNames(): array
    {
        return $this->defaultRoleNames;
    }

    public function getDefaultRoles(): array
    {
        return $this->filterStoredRoles($this->defaultRoleNames);
    }

    public function setGuestRoleName(?string $name): self
    {
        if ($name !== null && !$this->itemsStorage->roleExists($name)) {
            throw new InvalidArgumentException("Role \"$name\" does not exist.");
        }

        $this->guestRoleName = $name;
        return $this;
    }

    /**
     * Executes the rule associated with the specified role or permission.
     *
     * If the item does not specify a rule, this method will return `true`. Otherwise, it will
     * return the value of {@see RuleInterface::execute()}.
     *
     * @param string $userId The user ID. This should be a string representing the unique identifier of a user. For
     * guests the value is `null`.
     * @param Item $item The role or the permission that needs to execute its rule.
     * @param array $params Parameters passed to {@see AccessCheckerInterface::userHasPermission()} and will be passed
     * to the rule.
     *
     * @throws RuntimeException If the role or the permission has an invalid rule.
     * @return bool The return value of {@see RuleInterface::execute()}. If the role or the permission does not specify
     * a rule, `true` will be returned.
     */
    private function executeRule(?string $userId, Item $item, array $params): bool
    {
        if ($item->getRuleName() === null) {
            return true;
        }

        return $this->ruleFactory
            ->create($item->getRuleName())
            ->execute($userId, $item, new RuleContext($this->ruleFactory, $params));
    }

    /**
     * @throws ItemAlreadyExistsException
     */
    private function addItem(Permission|Role $item): void
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

    private function removeItem(string $name): void
    {
        if ($this->itemsStorage->exists($name)) {
            $this->itemsStorage->remove($name);
            $this->assignmentsStorage->removeByItemName($name);
        }
    }

    /**
     * @throws RuntimeException
     */
    private function assertFutureChild(string $parentName, string $childName): void
    {
        if ($parentName === $childName) {
            throw new RuntimeException("Cannot add \"$parentName\" as a child of itself.");
        }

        $parent = $this->itemsStorage->get($parentName);
        if ($parent === null) {
            throw new RuntimeException("Parent \"$parentName\" does not exist.");
        }

        $child = $this->itemsStorage->get($childName);
        if ($child === null) {
            throw new RuntimeException("Child \"$childName\" does not exist.");
        }

        if ($parent->getType() === Item::TYPE_PERMISSION && $child->getType() === Item::TYPE_ROLE) {
            throw new RuntimeException(
                "Can not add \"$childName\" role as a child of \"$parentName\" permission.",
            );
        }

        if ($this->itemsStorage->hasDirectChild($parentName, $childName)) {
            throw new RuntimeException("The item \"$parentName\" already has a child \"$childName\".");
        }

        if ($this->itemsStorage->hasChild($childName, $parentName)) {
            throw new RuntimeException(
                "Cannot add \"$childName\" as a child of \"$parentName\". A loop has been detected.",
            );
        }
    }

    private function assertItemNameForUpdate(Item $item, string $name): void
    {
        if ($item->getName() === $name || !$this->itemsStorage->exists($item->getName())) {
            return;
        }

        throw new InvalidArgumentException(
            'Unable to change the role or the permission name. ' .
            "The name \"{$item->getName()}\" is already used by another role or permission.",
        );
    }

    /**
     * @throws InvalidArgumentException
     * @return string[]
     */
    private function getDefaultRoleNamesForUpdate(array|Closure $roleNames): array
    {
        if (is_array($roleNames)) {
            $this->assertDefaultRoleNamesListForUpdate($roleNames);

            return $roleNames;
        }

        $roleNames = $roleNames();
        if (!is_array($roleNames)) {
            throw new InvalidArgumentException('Default role names closure must return an array.');
        }

        $this->assertDefaultRoleNamesListForUpdate($roleNames);

        return $roleNames;
    }

    /**
     * @psalm-assert string[] $roleNames
     *
     * @throws InvalidArgumentException
     */
    private function assertDefaultRoleNamesListForUpdate(array $roleNames): void
    {
        foreach ($roleNames as $roleName) {
            if (!is_string($roleName)) {
                throw new InvalidArgumentException('Each role name must be a string.');
            }
        }
    }

    /**
     * @param string[] $roleNames
     *
     * @throws DefaultRolesNotFoundException
     * @return array<string, Role>
     */
    private function filterStoredRoles(array $roleNames): array
    {
        $storedRoles = $this->itemsStorage->getRolesByNames($roleNames);
        $missingRoles = array_diff($roleNames, array_keys($storedRoles));
        if (!empty($missingRoles)) {
            $missingRolesStr = '"' . implode('", "', $missingRoles) . '"';

            throw new DefaultRolesNotFoundException("The following default roles were not found: $missingRolesStr.");
        }

        return $storedRoles;
    }
}
