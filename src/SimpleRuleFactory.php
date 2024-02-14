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

        $instance = new $name;
        if (!$instance instanceof RuleInterface) {
            throw new RuleInterfaceNotImplementedException($name);
        }

        return $instance;
    }
}
