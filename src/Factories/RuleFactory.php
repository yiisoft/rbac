<?php
/**
 * @link http://www.yiiframework.com/
 *
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license http://www.yiiframework.com/license/
 */

namespace Yiisoft\Rbac\Factories;

use Yiisoft\Rbac\Rule;

/**
 * @author Andrii Vasyliev <sol@hiqdev.com>
 *
 * @since 3.0
 */
class RuleFactory implements RuleFactoryInterface
{
    public function create(string $class): Rule
    {
        return new $class();
    }
}
