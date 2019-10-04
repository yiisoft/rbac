<?php
namespace Yiisoft\Rbac\RuleFactory;

use Yiisoft\Rbac\Rule;
use Yiisoft\Rbac\RuleFactoryInterface;

class RuleFactory implements RuleFactoryInterface
{
    public function create(string $class): Rule
    {
        return new $class();
    }
}
