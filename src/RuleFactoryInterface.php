<?php
/**
 * @link http://www.yiiframework.com/
 *
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license http://www.yiiframework.com/license/
 */

namespace Yiisoft\Rbac;

/**
 * @author Andrii Vasyliev <sol@hiqdev.com>
 *
 * @since 3.0
 */
interface RuleFactoryInterface
{
    /**
     * @param string|mixed $name class name or other rule definition.
     *
     * @return Rule created rule.
     */
    public function create($name): Rule;
}
