<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\RuleFactory;

use Yiisoft\Rbac\RuleInterface;
use Yiisoft\Rbac\RuleFactoryInterface;

/**
 * Creates rule instance based on its class name.
 */
final class ClassNameRuleFactory implements RuleFactoryInterface
{
    /**
     * @psalm-param class-string<RuleInterface> $name
     * @psalm-suppress UnsafeInstantiation
     */
    public function create(string $name): RuleInterface
    {
        return new $name();
    }
}
