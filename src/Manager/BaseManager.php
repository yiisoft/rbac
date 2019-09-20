<?php
namespace Yiisoft\Rbac\Manager;

use Yiisoft\Rbac\Assignment;
use Yiisoft\Rbac\Exceptions\InvalidArgumentException;
use Yiisoft\Rbac\Exceptions\InvalidConfigException;
use Yiisoft\Rbac\Exceptions\InvalidValueException;
use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\ItemInterface;
use Yiisoft\Rbac\ManagerInterface;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\Rule;
use Yiisoft\Rbac\Role;

/**
 * BaseManager is a base class implementing {@see ManagerInterface} for RBAC management.
 *
 * For more details and usage information on DbManager, see the [guide article on security authorization](guide:security-authorization).
 */
abstract class BaseManager implements ManagerInterface
{
    /**
     * @var array a list of role names that are assigned to every user automatically without calling [[assign()]].
     *            Note that these roles are applied to users, regardless of their state of authentication.
     */
    protected $defaultRoles = [];

    /**
     * Returns the named auth item.
     *
     * @param string $name the auth item name.
     *
     * @return Item the auth item corresponding to the specified name. Null is returned if no such item.
     */
    abstract protected function getItem(string $name): ?Item;

    /**
     * Returns the items of the specified type.
     *
     * @param int $type the auth item type (either [[Item::TYPE_ROLE]] or [[Item::TYPE_PERMISSION]]
     *
     * @return Item[] the auth items of the specified type.
     */
    abstract protected function getItems(int $type): array;

    /**
     * Adds an auth item to the RBAC system.
     *
     * @param Item $item the item to add
     *
     * @return void whether the auth item is successfully added to the system
     */
    abstract protected function addItem(Item $item): void;

    /**
     * Adds a rule to the RBAC system.
     *
     * @param Rule $rule the rule to add
     *
     * @return void whether the rule is successfully added to the system
     */
    abstract protected function addRule(Rule $rule): void;

    /**
     * Removes an auth item from the RBAC system.
     *
     * @param Item $item the item to remove
     *
     * @return void
     */
    abstract protected function removeItem(Item $item): void;

    /**
     * Removes a rule from the RBAC system.
     *
     * @param Rule $rule the rule to remove
     *
     * @return void
     */
    abstract protected function removeRule(Rule $rule): void;

    /**
     * Updates an auth item in the RBAC system.
     *
     * @param string $name the name of the item being updated
     * @param Item   $item the updated item
     *
     * @return void whether the auth item is successfully updated
     */
    abstract protected function updateItem(string $name, Item $item): void;

    /**
     * Updates a rule to the RBAC system.
     *
     * @param string $name the name of the rule being updated
     * @param Rule   $rule the updated rule
     *
     * @return void whether the rule is successfully updated
     */
    abstract protected function updateRule(string $name, Rule $rule): void;

    public function createRole(string $name): Role
    {
        return new Role($name);
    }

    public function createPermission(string $name): Permission
    {
        return new Permission($name);
    }

    public function add(ItemInterface $item): void
    {
        if ($item instanceof Item) {
            if ($item->getRuleName() !== '' && $this->getRule($item->getRuleName()) === null) {
                $rule = $this->createRule($item->getRuleName());
                $this->addRule($rule);
            }

            $this->addItem($item);
            return;
        }

        if ($item instanceof Rule) {
            $this->addRule($item);
            return;
        }

        throw new InvalidArgumentException('Adding unsupported object type.');
    }

    protected function createRule(string $name): Rule
    {
        return new Rule($name);
    }

    public function remove(ItemInterface $item): void
    {
        if ($item instanceof Item) {
            $this->removeItem($item);
            return;
        }

        if ($item instanceof Rule) {
            $this->removeRule($item);
            return;
        }

        throw new InvalidArgumentException('Removing unsupported item type.');
    }

    public function update(string $name, ItemInterface $object): void
    {
        if ($object instanceof Item) {
            if ($object->getRuleName() && $this->getRule($object->getRuleName()) === null) {
                $rule = $this->createRule($object->getRuleName());
                $this->addRule($rule);
            }

            $this->updateItem($name, $object);
            return;
        }

        if ($object instanceof Rule) {
            $this->updateRule($name, $object);
            return;
        }

        throw new InvalidArgumentException('Updating unsupported item type.');
    }

    public function getRole(string $name): ?Role
    {
        $item = $this->getItem($name);
        if ($item !== null && !($item instanceof Role)) {
            throw new InvalidValueException();
        }

        return $item;
    }

    public function getPermission(string $name): ?Permission
    {
        $item = $this->getItem($name);
        if (!($item instanceof Permission)) {
            return null;
        }

        return $item;
    }

    public function getRoles(): array
    {
        return $this->getItems(Item::TYPE_ROLE);
    }

    /**
     * Set default roles.
     *
     * @param string[]|callable $roles either array of roles or a callable returning it
     *
     * @return BaseManager
     * @throws InvalidArgumentException when $roles is neither array nor Closure
     * @throws InvalidValueException    when Closure return is not an array
     */
    public function setDefaultRoles($roles): self
    {
        if (is_array($roles)) {
            $this->defaultRoles = $roles;
            return $this;
        }

        if ($roles instanceof \Closure) {
            $roles = $roles();
            if (!is_array($roles)) {
                throw new InvalidValueException('Default roles closure must return an array');
            }
            $this->defaultRoles = $roles;
            return $this;
        }

        throw new InvalidArgumentException('Default roles must be either an array or a callable');
    }

    /**
     * Get default roles.
     *
     * @return string[] default roles
     */
    public function getDefaultRoles(): array
    {
        return $this->defaultRoles;
    }

    /**
     * Returns defaultRoles as array of Role objects.
     *
     * @return Role[] default roles. The array is indexed by the role names
     *
     */
    public function getDefaultRoleInstances(): array
    {
        $result = [];
        foreach ($this->defaultRoles as $roleName) {
            $result[$roleName] = $this->createRole($roleName);
        }

        return $result;
    }

    public function getPermissions(): array
    {
        return $this->getItems(Item::TYPE_PERMISSION);
    }

    /**
     * Executes the rule associated with the specified auth item.
     *
     * If the item does not specify a rule, this method will return true. Otherwise, it will
     * return the value of [[Rule::execute()]].
     *
     * @param string $user the user ID. This should be a string representing
     * the unique identifier of a user.
     * @param Item $item the auth item that needs to execute its rule
     * @param array $params parameters passed to {@see AccessCheckerInterface::hasPermission()} and will be passed to the rule
     *
     * @return bool the return value of {@see Rule::execute()}. If the auth item does not specify a rule, true will be
     * returned.
     * @throws InvalidConfigException if the auth item has an invalid rule.
     *
     */
    protected function executeRule(string $user, Item $item, array $params): bool
    {
        if ($item->getRuleName() === null) {
            return true;
        }
        $rule = $this->getRule($item->getRuleName());
        if ($rule === null) {
            throw new InvalidConfigException("Rule not found: {$item->getRuleName()}");
        }

        return $rule->execute($user, $item, $params);
    }

    /**
     * Checks whether array of $assignments is empty and [[defaultRoles]] property is empty as well.
     *
     * @param Assignment[] $assignments array of user's assignments
     *
     * @return bool whether array of $assignments is empty and [[defaultRoles]] property is empty as well
     */
    protected function hasNoAssignments(array $assignments): bool
    {
        return empty($assignments) && empty($this->defaultRoles);
    }
}
