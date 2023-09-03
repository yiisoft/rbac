<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Support;

use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\Role;
use Yiisoft\Rbac\ItemsStorageInterface;

final class FakeItemsStorage implements ItemsStorageInterface
{
    private array $items = [];
    private array $children = [];

    public function getAll(): array
    {
        return $this->items;
    }

    public function get(string $name): ?Item
    {
        return $this->items[$name] ?? null;
    }

    public function exists(string $name): bool
    {
        return array_key_exists($name, $this->items);
    }

    public function add(Item $item): void
    {
        $this->items[$item->getName()] = $item;
    }

    public function getRole(string $name): ?Role
    {
        return $this->getItemsByType(Item::TYPE_ROLE)[$name] ?? null;
    }

    public function getRoles(): array
    {
        return $this->getItemsByType(Item::TYPE_ROLE);
    }

    public function getRolesByNames(array $names): array
    {
        return array_filter(
            $this->getAll(),
            static fn (Item $item): bool => $item->getType() === Item::TYPE_ROLE && in_array($item->getName(), $names),
        );
    }

    public function getPermission(string $name): ?Permission
    {
        return $this->getItemsByType(Item::TYPE_PERMISSION)[$name] ?? null;
    }

    public function getPermissions(): array
    {
        return $this->getItemsByType(Item::TYPE_PERMISSION);
    }

    public function getPermissionsByNames(array $names): array
    {
        $permissionType = Item::TYPE_PERMISSION;

        return array_filter(
            $this->getAll(),
            static fn (Item $item): bool => $item->getType() === $permissionType && in_array($item->getName(), $names),
        );
    }

    public function getParents(string $name): array
    {
        $result = [];
        $this->fillParentsRecursive($name, $result);
        return $result;
    }

    public function getDirectChildren(string $name): array
    {
        return $this->children[$name] ?? [];
    }

    public function getAllChildren(string $name): array
    {
        $result = [];
        $this->fillChildrenRecursive($name, $result);
        return $result;
    }

    public function getAllChildRoles(string $name): array
    {
        $result = [];
        $this->fillChildrenRecursive($name, $result);
        return $this->filterRoles($result);
    }

    public function getAllChildPermissions(string $name): array
    {
        $result = [];
        $this->fillChildrenRecursive($name, $result);
        return $this->filterPermissions($result);
    }

    public function addChild(string $parentName, string $childName): void
    {
        $this->children[$parentName][$childName] = $this->items[$childName];
    }

    public function hasChildren(string $name): bool
    {
        return isset($this->children[$name]);
    }

    public function hasChild(string $parentName, string $childName): bool
    {
        return $this->hasLoop($childName, $parentName);
    }

    public function hasDirectChild(string $parentName, string $childName): bool
    {
        return isset($this->children[$parentName][$childName]);
    }

    public function removeChild(string $parentName, string $childName): void
    {
        unset($this->children[$parentName][$childName]);
    }

    public function removeChildren(string $parentName): void
    {
        unset($this->children[$parentName]);
    }

    public function remove(string $name): void
    {
        $this->clearChildrenFromItem($name);
        $this->removeItemByName($name);
    }

    public function update(string $name, Item $item): void
    {
        if ($item->getName() !== $name) {
            $this->updateItemName($name, $item);
            $this->removeItemByName($name);
        }

        $this->add($item);
    }

    public function clear(): void
    {
        $this->children = [];
        $this->items = [];
    }

    public function clearPermissions(): void
    {
        $this->removeItemsByType(Item::TYPE_PERMISSION);
    }

    public function clearRoles(): void
    {
        $this->removeItemsByType(Item::TYPE_ROLE);
    }

    private function updateItemName(string $name, Item $item): void
    {
        $this->updateChildrenForItemName($name, $item);
    }

    private function getItemsByType(string $type): array
    {
        return array_filter(
            $this->getAll(),
            static fn (Item $item): bool => $item->getType() === $type,
        );
    }

    private function removeItemsByType(string $type): void
    {
        foreach ($this->getItemsByType($type) as $item) {
            $this->remove($item->getName());
        }
    }

    private function clearChildrenFromItem(string $itemName): void
    {
        foreach ($this->children as &$children) {
            unset($children[$itemName]);
        }
    }

    private function updateChildrenForItemName(string $name, Item $item): void
    {
        if ($this->hasChildren($name)) {
            $this->children[$item->getName()] = $this->children[$name];
            unset($this->children[$name]);
        }
        foreach ($this->children as &$children) {
            if (isset($children[$name])) {
                $children[$item->getName()] = $item;
                unset($children[$name]);
            }
        }
    }

    private function removeItemByName(string $name): void
    {
        unset($this->items[$name]);
    }

    private function fillParentsRecursive(string $name, array &$result): void
    {
        foreach ($this->children as $parentName => $childItems) {
            foreach ($childItems as $childItem) {
                if ($childItem->getName() === $name) {
                    $result[$parentName] = $this->get($parentName);
                    $this->fillParentsRecursive($parentName, $result);
                    break;
                }
            }
        }
    }

    private function fillChildrenRecursive(string $name, array &$result): void
    {
        $children = $this->children[$name] ?? [];
        foreach ($children as $childName => $childItem) {
            $result[$childName] = $this->get($childName);
            $this->fillChildrenRecursive($childName, $result);
        }
    }

    /**
     * @param Item[] $array
     * @psalm-param array<string, Item> $array
     *
     * @return Role[]
     * @psalm-return array<string, Role>
     */
    private function filterRoles(array $array): array
    {
        return array_filter(
            $this->getRoles(),
            static fn (Role $roleItem): bool => array_key_exists($roleItem->getName(), $array),
        );
    }

    /**
     * @param Item[] $items
     * @psalm-param array<string, Item> $items
     *
     * @return Permission[]
     * @psalm-return array<string, Permission>
     */
    private function filterPermissions(array $items): array
    {
        $permissions = [];
        foreach (array_keys($items) as $permissionName) {
            $permission = $this->getPermission($permissionName);
            if ($permission !== null) {
                $permissions[$permissionName] = $permission;
            }
        }

        return $permissions;
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
        if ($parentName === $childName) {
            return true;
        }

        $children = $this->getDirectChildren($childName);
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
}
