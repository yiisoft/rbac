<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\RuleFactory;

use Yiisoft\Rbac\Rule;
use Yiisoft\Rbac\RuleFactoryInterface;

/**
 * Creates rule instance based on its class name.
 */
class ClassNameRuleFactory implements RuleFactoryInterface
{
    /**
     * @psalm-param class-string<Rule> $name
     */
    public function create(string $name): Rule
    {
        return new $name();
    }
}
