<?php
namespace Yiisoft\Rbac;

use Yiisoft\Factory\FactoryInterface;
use Yiisoft\Rbac\Factory\RuleFactoryInterface;

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
