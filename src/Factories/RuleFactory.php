<?php
namespace Yiisoft\Rbac;

class RuleFactory implements RuleFactoryInterface
{
    public function create(string $class): Rule
    {
        return new $class();
    }
}
