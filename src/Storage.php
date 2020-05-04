<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

interface Storage
{
    public function clear(): void;

    /**
     * @return Item[]
     */
    public function getItems(): array;

    /**
     * @param Item $item
     */
    public function addItem(Item $item): void;

    /**
     * @return array
     */
    public function getRoles(): array;

    /**
     * @param string $name
     * @return Role|null
     */
    public function getRoleByName(string $name): ?Role;


    /**
     * @return array|Permission[]
     */
    public function getPermissions(): array;

    /**
     * @param string $name
     * @return Permission|null
     */
    public function getPermissionByName(string $name): ?Permission;

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
     * @param string $type
     */
    public function removeAllItems(string $type): void;

    /**
     * @return array
     */
    public function getChildren(): array;

    /**
     * @param Item $parent
     * @param Item $child
     */
    public function addChildren(Item $parent, Item $child): void;

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
    public function getAssignmentsByUser(string $userId): array;

    /**
     * @param string $userId
     * @param Item $item
     */
    public function addAssignments(string $userId, Item $item): void;

    /**
     * @param string $name
     * @return bool
     */
    public function assignmentExist(string $name): bool;

    /**
     * @param string $userId
     * @param Item $item
     */
    public function removeAssignments(string $userId, Item $item): void;

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
    public function getRulesByName(string $name): ?Rule;

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
