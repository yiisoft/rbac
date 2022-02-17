<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Support;

use Yiisoft\Rbac\Exception\RuleNotFoundException;
use Yiisoft\Rbac\RuleFactoryInterface;
use Yiisoft\Rbac\RuleInterface;

use function array_key_exists;

final class SimpleRuleFactory implements RuleFactoryInterface
{
    /**
     * @psalm-var array<string,RuleInterface>
     */
    private array $rules;

    /**
     * @psalm-param array<string,RuleInterface> $rules
     */
    public function __construct(array $rules = [])
    {
        $this->rules = $rules;
    }

    public function create(string $name): RuleInterface
    {
        if (!array_key_exists($name, $this->rules)) {
            throw new RuleNotFoundException($name);
        }

        return $this->rules[$name];
    }
}
