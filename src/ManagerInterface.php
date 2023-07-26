<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

use Yiisoft\Access\AccessCheckerInterface;

interface ManagerInterface extends AccessCheckerInterface
{
    public function canAddChild(string $parentName, string $childName): bool;

    public function addChild(string $parentName, string $childName): self;

    public function removeChild(string $parentName, string $childName): self;

    public function removeChildren(string $parentName): self;

    public function hasChild(string $parentName, string $childName): bool;

    public function assign(string $itemName, $userId): self;

    public function revoke(string $itemName, $userId): self;

    public function revokeAll($userId): self;

    public function getRolesByUserId($userId): array;

    public function getChildRoles(string $roleName): array;

    public function getPermissionsByRoleName(string $roleName): array;

    public function getPermissionsByUserId($userId): array;

    public function getUserIdsByRoleName(string $roleName): array;

    public function addRole(Role $role): self;

    public function removeRole(string $name): self;

    public function updateRole(string $name, Role $role): self;

    public function addPermission(Permission $permission): self;

    public function removePermission(string $permissionName): self;

    public function updatePermission(string $name, Permission $permission): self;

    public function setDefaultRoleNames($roleNames): self;

    public function getDefaultRoleNames(): array;

    public function getDefaultRoles(): array;

    public function setGuestRoleName(?string $name): self;
}
