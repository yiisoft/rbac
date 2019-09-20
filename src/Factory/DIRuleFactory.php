<?php
/**
 * @link      http://www.yiiframework.com/
 *
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license   http://www.yiiframework.com/license/
 */

namespace Yiisoft\Rbac\Factory;

use Psr\Container\ContainerInterface;
use Yiisoft\Rbac\Rule;

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
