<?php

namespace Yiisoft\Rbac\Tests;

use Yiisoft\Rbac\Assignment;
use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\Manager\PhpManager;
use Yiisoft\Rbac\Rule;

/**
 * Exposes protected properties and methods to inspect from outside.
 */
class ExposedPhpManager extends PhpManager
{
    /**
     * @var Item[]
     */
    public array $items = []; // itemName => item
    /**
     * @var array
     */
    public array $children = []; // itemName, childName => child
    /**
     * @var Assignment[]
     */
    public array $assignments = []; // userId, itemName => assignment
    /**
     * @var Rule[]
     */
    public array $rules = []; // ruleName => rule

    public function load(): void
    {
        parent::load();
    }

    public function save(): void
    {
        parent::save();
    }
}
