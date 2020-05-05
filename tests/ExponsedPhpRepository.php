<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use Yiisoft\Rbac\Assignment;
use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\PhpRepository;
use Yiisoft\Rbac\Rule;

/**
 * Exposes protected properties and methods to inspect from outside.
 */
class ExponsedPhpRepository extends PhpRepository
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
}
