<?php
/**
 * @link      http://www.yiiframework.com/
 *
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license   http://www.yiiframework.com/license/
 */

namespace Yiisoft\Rbac\Factories;

use Psr\Container\ContainerInterface;
use Yiisoft\Rbac\Rule;

/**
 * @author Andrii Vasyliev <sol@hiqdev.com>
 * @author Dmitrii Derepko <xepozz@list.ru>
 *
 * @since  3.0
 */
class DIRuleFactory implements RuleFactoryInterface
{
    private $container;

    public function __construct(ContainerInterface $factory)
    {
        $this->container = $factory;
    }

    public function create(string $name): Rule
    {
        return $this->container->get($name);
    }
}
