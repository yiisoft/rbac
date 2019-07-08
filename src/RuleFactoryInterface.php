<?php
namespace Yiisoft\Rbac;

interface RuleFactoryInterface
{
    /**
     * @param string|mixed $name class name or other rule definition.
     *
     * @return Rule created rule.
     */
    public function create($name): Rule;
}
