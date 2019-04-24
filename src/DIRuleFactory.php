<?php
/**
 * @link http://www.yiiframework.com/
 *
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license http://www.yiiframework.com/license/
 */

namespace Yiisoft\Rbac;

use yii\di\FactoryInterface;

/**
 * @author Andrii Vasyliev <sol@hiqdev.com>
 *
 * @since 3.0
 */
class DIRuleFactory implements RuleFactoryInterface
{
    /**
     * @param mixed FactoryInterface $factory
     */
    public function __construct(FactoryInterface $factory)
    {
        $this->factory = $factory;
    }

    /**
     * {@inheritdoc}
     */
    public function create($name): Rule
    {
        return $this->factory->create($name);
    }
}
