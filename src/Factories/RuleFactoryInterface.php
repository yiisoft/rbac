<?php
namespace Yiisoft\Rbac;

interface RuleFactoryInterface
{
    /**
     * @param string $name class name or other rule definition.
     *
     * @return Rule created rule.
     */
    public function create(string $name): Rule;
}
