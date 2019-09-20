<?php
namespace Yiisoft\Rbac\Factory;

class RuleFactory implements RuleFactoryInterface
{
    public function create(string $class): Rule
    {
        return new $class();
    }
}
