<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\Role;
use Yiisoft\Rbac\Rule;
use Yiisoft\Rbac\RolesStorageInterface;

final class FakeRolesStorage implements RolesStorageInterface
{
    private array $items = [];

    private array $children = [];

    private array $rules = [];

    public function getItems(): array
    {
        return $this->items;
    }

    public function getItemByName(string $name): ?Item
    {
        return $this->items[$name] ?? null;
    }

    public function addItem(Item $item): void
    {
        $this->items[$item->getName()] = $item;
    }

    public function getRoleByName(string $name): ?Role
    {
        return $this->getItemsByType(Item::TYPE_ROLE)[$name] ?? null;
    }

    public function getRoles(): array
    {
        return $this->getItemsByType(Item::TYPE_ROLE);
    }

    public function getPermissionByName(string $name): ?Permission
    {
        return $this->getItemsByType(Item::TYPE_PERMISSION)[$name] ?? null;
    }

    public function getPermissions(): array
    {
        return $this->getItemsByType(Item::TYPE_PERMISSION);
    }

    public function getChildren(): array
    {
        return $this->children;
    }

    public function getChildrenByName(string $name): array
    {
        return $this->children[$name] ?? [];
    }

    public function getRules(): array
    {
        return $this->rules;
    }

    public function getRuleByName(string $name): ?Rule
    {
        return $this->rules[$name] ?? null;
    }

    public function addChild(Item $parent, Item $child): void
    {
        $this->children[$parent->getName()][$child->getName()] = $this->items[$child->getName()];
    }

    public function hasChildren(string $name): bool
    {
        return isset($this->children[$name]);
    }

    public function removeChild(Item $parent, Item $child): void
    {
        unset($this->children[$parent->getName()][$child->getName()]);
    }

    public function removeChildren(Item $parent): void
    {
        unset($this->children[$parent->getName()]);
    }

    public function removeItem(Item $item): void
    {
        $this->clearChildrenFromItem($item);
        $this->removeItemByName($item->getName());
    }

    public function updateItem(string $name, Item $item): void
    {
        if ($item->getName() !== $name) {
            $this->updateItemName($name, $item);
            $this->removeItemByName($name);
        }

        $this->addItem($item);
    }

    public function removeRule(string $name): void
    {
        unset($this->rules[$name]);
        foreach ($this->getItemsByRuleName($name) as $item) {
            $item = $item->withRuleName(null);
            $this->updateItem($item->getName(), $item);
        }
    }

    public function addRule(Rule $rule): void
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
        return array_filter($this->getItems(), $callback);
    }

    private function removeAllItems(string $type): void
    {
        foreach ($this->getItemsByType($type) as $name => $item) {
            $this->removeItem($item);
        }
    }

    private function clearChildrenFromItem(Item $item): void
    {
        foreach ($this->children as &$children) {
            unset($children[$item->getName()]);
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
