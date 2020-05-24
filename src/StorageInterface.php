<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

interface StorageInterface
{
    public function clear(): void;

    /**
     * @return Item[]
     */
    public function getItems(): array;

    /**
     * @param string $name
     * @return Item|null
     */
    public function getItemByName(string $name): ?Item;

    /**
     * @param Item $item
     */
    public function addItem(Item $item): void;

    /**
     * @param string $name
     * @param Item $item
     */
    public function updateItem(string $name, Item $item): void;

    /**
     * @param Item $item
     */
    public function removeItem(Item $item): void;

    /**
     * @return array
     */
    public function getChildren(): array;

    /**
     * @return array
     */
    public function getRoles(): array;

    /**
     * @param string $name
     * @return Role|null
     */
    public function getRoleByName(string $name): ?Role;

    public function clearRoles(): void;

    /**
     * @return array|Permission[]
     */
    public function getPermissions(): array;

    /**
     * @param string $name
     * @return Permission|null
     */
    public function getPermissionByName(string $name): ?Permission;

    public function clearPermissions(): void;

    /**
     * @param string $name
     * @return array|Item[]
     */
    public function getChildrenByName(string $name): array;

    /**
     * @param string $name
     * @return bool
     */
    public function hasChildren(string $name): bool;

    /**
     * @param Item $parent
     * @param Item $child
     */
    public function addChild(Item $parent, Item $child): void;

    /**
     * @param Item $parent
     * @param Item $child
     */
    public function removeChild(Item $parent, Item $child): void;

    /**
     * @param Item $parent
     */
    public function removeChildren(Item $parent): void;

    /**
     * @return array
     */
    public function getAssignments(): array;

    /**
     * @param string $userId
     * @return array
     */
    public function getUserAssignments(string $userId): array;

    /**
     * @param string $userId
     * @param string $name
     * @return Assignment|null
     */
    public function getUserAssignmentByName(string $userId, string $name): ?Assignment;

    /**
     * @param string $userId
     * @param Item $item
     */
    public function addAssignment(string $userId, Item $item): void;

    /**
     * @param string $name
     * @return bool
     */
    public function assignmentExist(string $name): bool;

    /**
     * @param string $userId
     * @param Item $item
     */
    public function removeAssignment(string $userId, Item $item): void;

    /**
     * @param string $userId
     */
    public function removeAllAssignments(string $userId): void;

    public function clearAssignments(): void;

    /**
     * @return Rule[]
     */
    public function getRules(): array;

    /**
     * @param string $name
     * @return Rule|null
     */
    public function getRuleByName(string $name): ?Rule;

    /**
     * @param string $name
     */
    public function removeRule(string $name): void;

    /**
     * @param Rule $rule
     */
    public function addRule(Rule $rule): void;

    public function clearRules(): void;
}
