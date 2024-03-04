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
    private readonly RuleFactoryInterface $ruleFactory;
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
     * @param bool $includeRolesInAccessChecks Whether to include roles (in addition to permissions) during access
     * checks in {@see Manager::userHasPermission()}.
     */
    public function __construct(
        private readonly ItemsStorageInterface $itemsStorage,
        private readonly AssignmentsStorageInterface $assignmentsStorage,
        ?RuleFactoryInterface $ruleFactory = null,
        private readonly bool $enableDirectPermissions = false,
        private readonly bool $includeRolesInAccessChecks = false,
    ) {
        $this->ruleFactory = $ruleFactory ?? new SimpleRuleFactory();
    }

    public function userHasPermission(
        int|string|Stringable|null $userId,
        string $permissionName,
        array $parameters = [],
    ): bool {
        $item = $this->itemsStorage->get($permissionName);
        if ($item === null) {
            return false;
        }

        if (!$this->includeRolesInAccessChecks && $item->getType() === Item::TYPE_ROLE) {
            return false;
        }

        if ($userId !== null) {
            $guestRole = null;
        } else {
            $guestRole = $this->getGuestRole();
            if ($guestRole === null) {
                return false;
            }
        }

        $hierarchy = $this->itemsStorage->getHierarchy($item->getName());
        $itemNames = array_map(static fn (array $treeItem): string => $treeItem['item']->getName(), $hierarchy);
        $userItemNames = $guestRole !== null
            ? [$guestRole->getName()]
            : $this->assignmentsStorage->filterUserItemNames((string) $userId, $itemNames);
        $userItemNamesMap = [];
        foreach ($userItemNames as $userItemName) {
            $userItemNamesMap[$userItemName] = null;
        }

        foreach ($hierarchy as $data) {
            if (
                !array_key_exists($data['item']->getName(), $userItemNamesMap) ||
                !$this->executeRule($userId === null ? $userId : (string) $userId, $data['item'], $parameters)
            ) {
                continue;
            }

            $hasPermission = true;
            foreach ($data['children'] as $childItem) {
                if (!$this->executeRule($userId === null ? $userId : (string) $userId, $childItem, $parameters)) {
                    $hasPermission = false;

                    /**
                     * @infection-ignore-all Break_
                     * Replacing with `continue` works as well, but there is no point in further checks, because at
                     * least one failed rule execution means access is not granted via current iterated hierarchy
                     * branch.
                     */
                    break;
                }
            }

            if ($hasPermission) {
                return true;
            }
        }

        return false;
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
            return $this;
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
        $assignmentNames = array_keys($assignments);

        return array_merge(
            $this->getDefaultRoles(),
            $this->itemsStorage->getByNames($assignmentNames),
            $this->itemsStorage->getAllChildren($assignmentNames),
        );
    }

    public function getRolesByUserId(int|Stringable|string $userId): array
    {
        $userId = (string) $userId;
        $assignments = $this->assignmentsStorage->getByUserId($userId);
        $assignmentNames = array_keys($assignments);

        return array_merge(
            $this->getDefaultRoles(),
            $this->itemsStorage->getRolesByNames($assignmentNames),
            $this->itemsStorage->getAllChildRoles($assignmentNames)
        );
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
        if (empty($assignments)) {
            return [];
        }

        $assignmentNames = array_keys($assignments);

        return array_merge(
            $this->itemsStorage->getPermissionsByNames($assignmentNames),
            $this->itemsStorage->getAllChildPermissions($assignmentNames),
        );
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
        $this->defaultRoleNames = $this->getDefaultRoleNamesForUpdate($roleNames);

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
        $this->guestRoleName = $name;

        return $this;
    }

    public function getGuestRoleName(): ?string
    {
        return $this->guestRoleName;
    }

    public function getGuestRole(): ?Role
    {
        if ($this->guestRoleName === null) {
            return null;
        }

        $role = $this->getRole($this->guestRoleName);
        if ($role === null) {
            throw new RuntimeException("Guest role with name \"$this->guestRoleName\" does not exist.");
        }

        return $role;
    }

    /**
     * Executes the rule associated with the specified role or permission.
     *
     * If the item does not specify a rule, this method will return `true`. Otherwise, it will
     * return the value of {@see RuleInterface::execute()}.
     *
     * @param string|null $userId The user ID. This should be a string representing the unique identifier of a user. For
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

        if ($parent instanceof Permission && $child instanceof Role) {
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
