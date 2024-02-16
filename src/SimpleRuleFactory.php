<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

use Yiisoft\Rbac\Exception\RuleInterfaceNotImplementedException;
use Yiisoft\Rbac\Exception\RuleNotFoundException;

final class SimpleRuleFactory implements RuleFactoryInterface
{
    public function create(string $name): RuleInterface
    {
        if (!class_exists($name)) {
            throw new RuleNotFoundException($name);
        }

        if (!is_a($name, RuleInterface::class, allow_string: true)) {
            throw new RuleInterfaceNotImplementedException($name);
        }

        return new $name();
    }
}
