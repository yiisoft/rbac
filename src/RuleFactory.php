<?php
/**
 * @link http://www.yiiframework.com/
 *
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license http://www.yiiframework.com/license/
 */

namespace yii\rbac;

/**
 * @author Andrii Vasyliev <sol@hiqdev.com>
 *
 * @since 3.0
 */
class RuleFactory implements RuleFactoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function create($class): Rule
    {
        return new $class();
    }
}
