<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

use Yiisoft\Rbac\Exception\RuleNotFoundException;

use function array_key_exists;

final class SimpleRuleFactory implements RuleFactoryInterface
{
    /**
     * @psalm-param array<string,RuleInterface> $rules
     */
    public function __construct(private readonly array $rules = [])
    {
    }

    public function create(string $name): RuleInterface
    {
        if (!array_key_exists($name, $this->rules)) {
            throw new RuleNotFoundException($name);
        }

        return $this->rules[$name];
    }
}
