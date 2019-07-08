<?php
namespace Yiisoft\Rbac;

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
