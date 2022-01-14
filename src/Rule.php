<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

/**
 * Rule represents a business constraint that may be associated with a role, permission or assignment.
 */
abstract class Rule implements RuleInterface
{
    private string $name;

    public function __construct(string $name)
    {
        $this->name = $name;
    }

    /**
     * @inheritdoc
     */
    abstract public function execute(string $userId, Item $item, array $parameters = []): bool;

    final public function getName(): string
    {
        return $this->name;
    }

    final public function withName(string $name): self
    {
        $new = clone $this;
        $new->name = $name;
        return $new;
    }
}
