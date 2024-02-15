<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

final class RuleContext
{
    public function __construct(
        private readonly RuleFactoryInterface $ruleFactory,
        private readonly array $parameters = [],
    ) {
    }

    public function getParameters(): array
    {
        return $this->parameters;
    }

    public function getParameterValue(string $name): mixed
    {
        return $this->parameters[$name] ?? null;
    }

    public function hasParameter(string $name): bool
    {
        return array_key_exists($name, $this->parameters);
    }

    public function createRule(string $name): RuleInterface
    {
        return $this->ruleFactory->create($name);
    }
}
