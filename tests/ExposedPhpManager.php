<?php
/**
 * @link http://www.yiiframework.com/
 *
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license http://www.yiiframework.com/license/
 */

namespace Yiisoft\Rbac\Tests;

use Yiisoft\Rbac\Managers\PhpManager;

/**
 * Exposes protected properties and methods to inspect from outside.
 */
class ExposedPhpManager extends PhpManager
{
    /**
     * @var \Yiisoft\Rbac\Item[]
     */
    public $items = []; // itemName => item
    /**
     * @var array
     */
    public $children = []; // itemName, childName => child
    /**
     * @var \Yiisoft\Rbac\Assignment[]
     */
    public $assignments = []; // userId, itemName => assignment
    /**
     * @var \Yiisoft\Rbac\Rule[]
     */
    public $rules = []; // ruleName => rule

    public function load()
    {
        parent::load();
    }

    public function save()
    {
        parent::save();
    }
}
