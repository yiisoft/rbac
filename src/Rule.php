<?php

namespace Yiisoft\Rbac;

/**
 * Rule represents a business constraint that may be associated with a role, permission or assignment.
 */
abstract class Rule implements ItemInterface
{
    private $name;

    public function __construct(string $name)
    {
        $this->name = $name;
    }

    /**
     * @var int UNIX timestamp representing the rule creation time
     */
    public $createdAt;
    /**
     * @var int UNIX timestamp representing the rule updating time
     */
    public $updatedAt;

    /**
     * Executes the rule.
     *
     * @param string $userId the user ID. This should be a string representing
     * the unique identifier of a user.
     * @param Item $item the role or permission that this rule is associated with
     * @param array $parameters parameters passed to {@see CheckAccessInterface::hasPermission()}.
     *
     * @return bool whether the rule permits the auth item it is associated with.
     */
    abstract public function execute(string $userId, Item $item, array $parameters = []): bool;

    public function getName(): string
    {
        return $this->name;
    }
}
