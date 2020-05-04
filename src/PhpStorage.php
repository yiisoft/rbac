<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

use Yiisoft\Rbac\Exceptions\InvalidArgumentException;
use Yiisoft\VarDumper\VarDumper;

class PhpStorage implements Storage
{
    /**
     * @var string the path of the PHP script that contains the authorization items.
     * This can be either a file path or a [path alias](guide:concept-aliases) to the file.
     * Make sure this file is writable by the Web server process if the authorization needs to be changed
     * online.
     *
     * @see loadFromFile()
     * @see saveToFile()
     */
    protected string $itemFile;
    /**
     * @var string the path of the PHP script that contains the authorization assignments.
     * This can be either a file path or a [path alias](guide:concept-aliases) to the file.
     * Make sure this file is writable by the Web server process if the authorization needs to be changed
     * online.
     *
     * @see loadFromFile()
     * @see saveToFile()
     */
    protected string $assignmentFile;
    /**
     * @var string the path of the PHP script that contains the authorization rules.
     * This can be either a file path or a [path alias](guide:concept-aliases) to the file.
     * Make sure this file is writable by the Web server process if the authorization needs to be changed
     * online.
     *
     * @see loadFromFile()
     * @see saveToFile()
     */
    protected string $ruleFile;

    /**
     * @var Item[]
     * format [itemName => item]
     */
    protected array $items = [];

    /**
     * @var array
     * format [itemName => [childName => child]]
     */
    protected array $children = [];

    /**
     * @var array
     * format [userId => [itemName => assignment]]
     */
    protected array $assignments = [];

    /**
     * @var Rule[]
     * format [ruleName => rule]
     */
    protected array $rules = [];

    public function __construct(
        string $directory,
        string $itemFile = 'items.php',
        string $assignmentFile = 'assignments.php',
        string $ruleFile = 'rules.php'
    ) {
        $this->itemFile = $directory . DIRECTORY_SEPARATOR . $itemFile;
        $this->assignmentFile = $directory . DIRECTORY_SEPARATOR . $assignmentFile;
        $this->ruleFile = $directory . DIRECTORY_SEPARATOR . $ruleFile;
        $this->load();
    }

    /**
     * @return Item[]
     */
    public function getItems(): array
    {
        return $this->items;
    }

    /**
     * @param Item $item
     */
    public function addItem(Item $item): void
    {
        $this->items[$item->getName()] = $item;
        $this->saveItems();
    }

    /**
     * @param string $name
     * @return Role|null
     */
    public function getRoleByName(string $name): ?Role
    {
        return $this->getItemsByType(Item::TYPE_ROLE)[$name] ?? null;
    }

    /**
     * @return array|Role[]
     */
    public function getRoles(): array
    {
        return $this->getItemsByType(Item::TYPE_ROLE);
    }

    /**
     * @param string $name
     * @return Permission|null
     */
    public function getPermissionByName(string $name): ?Permission
    {
        return $this->getItemsByType(Item::TYPE_PERMISSION)[$name] ?? null;
    }

    /**
     * @return array
     */
    public function getPermissions(): array
    {
        return $this->getItemsByType(Item::TYPE_PERMISSION);
    }

    /**
     * @return array
     */
    public function getChildren(): array
    {
        return $this->children;
    }

    /**
     * @return array
     */
    public function getAssignments(): array
    {
        return $this->assignments;
    }

    /**
     * @param string $userId
     * @return array
     */
    public function getAssignmentsByUser(string $userId): array
    {
        return $this->assignments[$userId] ?? [];
    }

    /**
     * @return Rule[]
     */
    public function getRules(): array
    {
        return $this->rules;
    }

    /**
     * @param string $name
     * @return Rule|null
     */
    public function getRulesByName(string $name): ?Rule
    {
        return $this->rules[$name] ?? null;
    }

    public function addChildren(Item $parent, Item $child): void
    {
        $this->children[$parent->getName()][$child->getName()] = $this->items[$child->getName()];
        $this->saveItems();
    }

    public function removeChild(Item $parent, Item $child): void
    {
        unset($this->children[$parent->getName()][$child->getName()]);
        $this->saveItems();
    }

    public function removeChildren(Item $parent): void
    {
        unset($this->children[$parent->getName()]);
        $this->saveItems();
    }

    public function addAssignments(string $userId, Item $item): void
    {
        $this->assignments[$userId][$item->getName()] = new Assignment($userId, $item->getName(), time());
        $this->saveAssignments();
    }

    public function assignmentExist(string $name): bool
    {
        foreach ($this->getAssignments() as $assignment) {
            foreach ($assignment as $assignmentName => $object) {
                if ($assignmentName === $name) {
                    return true;
                }
            }
        }
        return false;
    }

    public function removeAssignments(string $userId, Item $item): void
    {
        unset($this->assignments[$userId][$item->getName()]);
        $this->saveAssignments();
    }

    public function removeAllAssignments(string $userId): void
    {
        foreach ($this->assignments[$userId] as $itemName => $value) {
            unset($this->assignments[$userId][$itemName]);
        }
        $this->saveAssignments();
    }

    /**
     * @param Item $item
     */
    public function removeItem(Item $item): void
    {
        foreach ($this->children as &$children) {
            unset($children[$item->getName()]);
        }
        unset($children);
        foreach ($this->assignments as &$assignments) {
            unset($assignments[$item->getName()]);
        }
        unset($assignments, $this->items[$item->getName()]);
        $this->saveItems();
        $this->saveAssignments();
    }

    public function updateItem(string $name, Item $item): void
    {
        if ($name !== $item->getName()) {
            if ($this->hasItem($item->getName())) {
                throw new InvalidArgumentException(
                    "Unable to change the item name. The name '{$item->getName()}' is already used by another item."
                );
            }

            // Remove old item in case of renaming
            unset($this->items[$name]);

            if (isset($this->children[$name])) {
                $this->children[$item->getName()] = $this->children[$name];
                unset($this->children[$name]);
            }
            foreach ($this->children as &$children) {
                if (isset($children[$name])) {
                    $children[$item->getName()] = $children[$name];
                    unset($children[$name]);
                }
            }
            unset($children);

            foreach ($this->assignments as &$assignments) {
                if (isset($assignments[$name])) {
                    $assignments[$item->getName()] = $assignments[$name]->withItemName($item->getName());
                    unset($assignments[$name]);
                }
            }
            unset($assignments);

            $this->saveAssignments();
        }

        $this->items[$item->getName()] = $item;

        $this->saveItems();
    }

    public function removeRule(string $name): void
    {
        unset($this->rules[$name]);
    }

    public function addRule(Rule $rule): void
    {
        $this->rules[$rule->getName()] = $rule;
        $this->saveRules();
    }

    public function clear(): void
    {
        $this->children = [];
        $this->items = [];
        $this->assignments = [];
        $this->rules = [];
        $this->save();
    }

    /**
     * Removes all auth items of the specified type.
     *
     * @param string $type the auth item type (either Item::TYPE_PERMISSION or Item::TYPE_ROLE)
     */
    public function removeAllItems(string $type): void
    {
        $names = [];
        foreach ($this->items as $name => $item) {
            if ($item->getType() === $type) {
                unset($this->items[$name]);
                $names[$name] = true;
            }
        }
        if (empty($names)) {
            return;
        }

        foreach ($this->assignments as $i => $assignments) {
            foreach ($assignments as $n => $assignment) {
                if (isset($names[$assignment->getItemName()])) {
                    unset($this->assignments[$i][$n]);
                }
            }
        }
        foreach ($this->children as $name => $children) {
            if (isset($names[$name])) {
                unset($this->children[$name]);
            } else {
                foreach ($children as $childName => $item) {
                    if (isset($names[$childName])) {
                        unset($children[$childName]);
                    }
                }
                $this->children[$name] = $children;
            }
        }

        $this->saveItems();
    }

    public function clearRules(): void
    {
        foreach ($this->items as &$item) {
            $item = $item->withRuleName(null);
        }
        unset($item);
        $this->rules = [];
        $this->saveRules();
    }

    public function clearAssignments(): void
    {
        $this->assignments = [];
        $this->saveAssignments();
    }

    /**
     * Saves authorization data into persistent storage.
     */
    private function save(): void
    {
        $this->saveItems();
        $this->saveAssignments();
        $this->saveRules();
    }

    /**
     * Loads authorization data from persistent storage.
     */
    private function load(): void
    {
        $this->children = [];
        $this->rules = [];
        $this->assignments = [];
        $this->items = [];

        $items = $this->loadFromFile($this->itemFile);
        $itemsMtime = @filemtime($this->itemFile);
        $assignments = $this->loadFromFile($this->assignmentFile);
        $assignmentsMtime = @filemtime($this->assignmentFile);
        $rules = $this->loadFromFile($this->ruleFile);

        foreach ($items as $name => $item) {
            $class = $item['type'] === Item::TYPE_PERMISSION ? Permission::class : Role::class;

            $this->items[$name] = (new $class($name))
                ->withDescription($item['description'] ?? '')
                ->withRuleName($item['ruleName'] ?? null)
                ->withCreatedAt($itemsMtime)
                ->withUpdatedAt($itemsMtime);
        }

        foreach ($items as $name => $item) {
            if (isset($item['children'])) {
                foreach ($item['children'] as $childName) {
                    if ($this->hasItem($childName)) {
                        $this->children[$name][$childName] = $this->items[$childName];
                    }
                }
            }
        }

        foreach ($assignments as $userId => $roles) {
            foreach ($roles as $role) {
                $this->assignments[$userId][$role] = new Assignment($userId, $role, $assignmentsMtime);
            }
        }

        foreach ($rules as $name => $ruleData) {
            $this->rules[$name] = unserialize($ruleData);
        }
    }

    protected function hasItem(string $name): bool
    {
        return isset($this->items[$name]);
    }

    /**
     * Loads the authorization data from a PHP script file.
     *
     * @param string $file the file path.
     *
     * @return array the authorization data
     *
     * @see saveToFile()
     */
    protected function loadFromFile(string $file): array
    {
        if (is_file($file)) {
            return require $file;
        }

        return [];
    }

    /**
     * Saves items data into persistent storage.
     */
    protected function saveItems(): void
    {
        $items = [];
        foreach ($this->items as $name => $item) {
            /* @var $item Item */
            $items[$name] = array_filter($item->getAttributes());
            if (isset($this->children[$name])) {
                foreach ($this->children[$name] as $child) {
                    /* @var $child Item */
                    $items[$name]['children'][] = $child->getName();
                }
            }
        }
        $this->saveToFile($items, $this->itemFile);
    }

    /**
     * Saves the authorization data to a PHP script file.
     *
     * @param array $data the authorization data
     * @param string $file the file path.
     *
     * @see loadFromFile()
     */
    protected function saveToFile(array $data, string $file): void
    {
        if (!file_exists(dirname($file)) && !mkdir($concurrentDirectory = dirname($file)) && !is_dir(
                $concurrentDirectory
            )) {
            throw new \RuntimeException(sprintf('Directory "%s" was not created', $concurrentDirectory));
        }

        file_put_contents($file, "<?php\nreturn " . VarDumper::create($data)->export() . ";\n", LOCK_EX);
        $this->invalidateScriptCache($file);
    }

    /**
     * Invalidates precompiled script cache (such as OPCache) for the given file.
     *
     * @param string $file the file path.
     */
    protected function invalidateScriptCache(string $file): void
    {
        if (function_exists('opcache_invalidate')) {
            opcache_invalidate($file, true);
        }
    }

    /**
     * Saves assignments data into persistent storage.
     */
    protected function saveAssignments(): void
    {
        $assignmentData = [];
        foreach ($this->assignments as $userId => $assignments) {
            foreach ($assignments as $assignment) {
                /* @var $assignment Assignment */
                $assignmentData[$userId][] = $assignment->getItemName();
            }
        }
        $this->saveToFile($assignmentData, $this->assignmentFile);
    }

    /**
     * Saves rules data into persistent storage.
     */
    protected function saveRules(): void
    {
        $rules = [];
        foreach ($this->rules as $name => $rule) {
            $rules[$name] = serialize($rule);
        }
        $this->saveToFile($rules, $this->ruleFile);
    }

    protected function getItemsByType(string $type): array
    {
        $items = [];

        foreach ($this->getItems() as $name => $item) {
            if ($item->getType() === $type) {
                $items[$name] = $item;
            }
        }

        return $items;
    }
}
