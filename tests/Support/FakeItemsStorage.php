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

    public function getByNames(array $names): array
    {
        return array_filter($this->getAll(), static fn (Item $item): bool => in_array($item->getName(), $names));
    }

    public function get(string $name): Permission|Role|null
    {
        return $this->items[$name] ?? null;
    }

    public function exists(string $name): bool
    {
        return array_key_exists($name, $this->items);
    }

    public function roleExists(string $name): bool
    {
        return isset($this->getItemsByType(Item::TYPE_ROLE)[$name]);
    }

    public function add(Permission|Role $item): void
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
        return array_filter(
            $this->getAll(),
            static function (Item $item) use ($names): bool {
                return $item->getType() === Item::TYPE_PERMISSION && in_array($item->getName(), $names);
            },
        );
    }

    public function getParents(string $name): array
    {
        $result = [];
        $this->fillParentsRecursive($name, $result);
        return $result;
    }

    public function getAccessTree(string $name): array
    {
        $result = [$name => ['item' => $this->items[$name], 'children' => []]];
        $this->fillAccessTreeRecursive($name, $result);

        return $result;
    }

    public function getDirectChildren(string $name): array
    {
        return $this->children[$name] ?? [];
    }

    public function getAllChildren(string|array $names): array
    {
        $result = [];
        $this->getAllChildrenInternal($names, $result);

        return $result;
    }

    public function getAllChildRoles(string|array $names): array
    {
        $result = [];
        $this->getAllChildrenInternal($names, $result);

        return $this->filterRoles($result);
    }

    public function getAllChildPermissions(string|array $names): array
    {
        $result = [];
        $this->getAllChildrenInternal($names, $result);

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
        if ($parentName === $childName) {
            return true;
        }

        $children = $this->getDirectChildren($parentName);
        if (empty($children)) {
            return false;
        }

        foreach ($children as $groupChild) {
            if ($this->hasChild($groupChild->getName(), $childName)) {
                return true;
            }
        }

        return false;
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

    public function update(string $name, Permission|Role $item): void
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
        unset($this->children[$itemName]);
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
                if ($childItem->getName() !== $name) {
                    continue;
                }

                $parent = $this->get($parentName);
                if ($parent !== null) {
                    $result[$parentName] = $parent;
                }

                $this->fillParentsRecursive($parentName, $result);

                break;
            }
        }
    }

    private function fillAccessTreeRecursive(string $name, array &$result, array $addedChildItems = []): void
    {
        foreach ($this->children as $parentName => $childItems) {
            foreach ($childItems as $childItem) {
                if ($childItem->getName() !== $name) {
                    continue;
                }

                $parent = $this->get($parentName);
                if ($parent !== null) {
                    $result[$parentName]['item'] = $this->items[$parentName];

                    $addedChildItems[$childItem->getName()] = $childItem;
                    $result[$parentName]['children'] = $addedChildItems;
                }

                $this->fillAccessTreeRecursive($parentName, $result, $addedChildItems);

                break;
            }
        }
    }

    private function getAllChildrenInternal(string|array $names, array &$result): void
    {
        $names = (array) $names;
        foreach ($names as $name) {
            $this->fillChildrenRecursive($name, $result);
        }
    }

    private function fillChildrenRecursive(string $name, array &$result): void
    {
        $children = $this->children[$name] ?? [];
        foreach ($children as $childName => $_childItem) {
            $child = $this->get($childName);
            if ($child !== null) {
                $result[$childName] = $child;
            }

            $this->fillChildrenRecursive($childName, $result);
        }
    }

    /**
     * @return Role[]
     */
    private function filterRoles(array $items): array
    {
        return array_filter($items, static fn (Permission|Role $item): bool => $item instanceof Role);
    }

    /**
     * @return Permission[]
     */
    private function filterPermissions(array $items): array
    {
        return array_filter($items, static fn (Permission|Role $item): bool => $item instanceof Permission);
    }
}
