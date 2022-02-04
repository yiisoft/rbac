<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Support;

use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\Role;
use Yiisoft\Rbac\RuleInterface;
use Yiisoft\Rbac\ItemsStorageInterface;

final class FakeItemsStorage implements ItemsStorageInterface
{
    private array $items = [];

    private array $children = [];

    private array $rules = [];

    public function getAll(): array
    {
        return $this->items;
    }

    public function get(string $name): ?Item
    {
        return $this->items[$name] ?? null;
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

    public function getPermission(string $name): ?Permission
    {
        return $this->getItemsByType(Item::TYPE_PERMISSION)[$name] ?? null;
    }

    public function getPermissions(): array
    {
        return $this->getItemsByType(Item::TYPE_PERMISSION);
    }

    public function getParents(string $name): array
    {
        $result = [];
        $this->getParentsRecursive($name, $result);
        return $result;
    }

    private function getParentsRecursive(string $name, array &$result): void
    {
        foreach ($this->children as $parentName => $items) {
            foreach ($items as $item) {
                if ($item->getName() === $name) {
                    $result[$parentName] = $this->get($parentName);
                    $this->getParentsRecursive($parentName, $result);
                    break;
                }
            }
        }
    }

    public function getChildren(string $name): array
    {
        return $this->children[$name] ?? [];
    }

    public function getRules(): array
    {
        return $this->rules;
    }

    public function getRule(string $name): ?RuleInterface
    {
        return $this->rules[$name] ?? null;
    }

    public function addChild(string $parentName, string $childName): void
    {
        $this->children[$parentName][$childName] = $this->items[$childName];
    }

    public function hasChildren(string $name): bool
    {
        return isset($this->children[$name]);
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

    public function removeRule(string $name): void
    {
        unset($this->rules[$name]);
        foreach ($this->getItemsByRuleName($name) as $item) {
            $item = $item->withRuleName(null);
            $this->update($item->getName(), $item);
        }
    }

    public function addRule(RuleInterface $rule): void
    {
        $this->rules[$rule->getName()] = $rule;
    }

    public function clear(): void
    {
        $this->children = [];
        $this->rules = [];
        $this->items = [];
    }

    public function clearRules(): void
    {
        $this->clearItemsFromRules();
        $this->rules = [];
    }

    public function clearPermissions(): void
    {
        $this->removeAllItems(Item::TYPE_PERMISSION);
    }

    public function clearRoles(): void
    {
        $this->removeAllItems(Item::TYPE_ROLE);
    }

    private function updateItemName(string $name, Item $item): void
    {
        $this->updateChildrenForItemName($name, $item);
    }

    private function getItemsByType(string $type): array
    {
        return $this->filterItems(
            fn (Item $item) => $item->getType() === $type
        );
    }

    private function getItemsByRuleName(string $ruleName): array
    {
        return $this->filterItems(
            fn (Item $item) => $item->getRuleName() === $ruleName
        );
    }

    /**
     * @param callable $callback
     *
     * @return array|Item[]
     */
    private function filterItems(callable $callback): array
    {
        return array_filter($this->getAll(), $callback);
    }

    private function removeAllItems(string $type): void
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
                $children[$item->getName()] = $children[$name];
                unset($children[$name]);
            }
        }
    }

    private function removeItemByName(string $name): void
    {
        unset($this->items[$name]);
    }

    private function clearItemsFromRules(): void
    {
        foreach ($this->items as &$item) {
            $item = $item->withRuleName(null);
        }
    }
}
