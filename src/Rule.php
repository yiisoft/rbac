<?php

namespace Yiisoft\Rbac;

/**
 * Rule represents a business constraint that may be associated with a role, permission or assignment.
 */
abstract class Rule implements ItemInterface
{
    private string $name;

    public function __construct(string $name)
    {
        $this->name = $name;
    }

    /**
     * Executes the rule.
     *
     * @param string $userId the user ID. This should be a string representing
     * the unique identifier of a user.
     * @param Item $item the role or permission that this rule is associated with
     * @param array $parameters parameters passed to {@see CheckAccessInterface::userHasPermission()}.
     *
     * @return bool whether the rule permits the auth item it is associated with.
     */
    public function execute(string $userId, Item $item, array $parameters = []): bool
    {
        return true;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function withName(string $name): self
    {
        $new = clone $this;
        $new->name = $name;
        return $new;
    }

    public function getAttributes(): array
    {
        return [
            'name' => $this->getName()
        ];
    }
}
