<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

/**
 * Rule represents a business constraint that may be associated with a role or a permission.
 */
interface RuleInterface
{
    /**
     * Executes the rule.
     *
     * @param string $userId The user ID. This should be a string representing the unique identifier of a user.
     * @param Item $item The role or permission that this rule is associated with.
     * @param RuleFactoryInterface $ruleFactory Rule factory.
     * @param array $parameters Parameters passed to {@see CheckAccessInterface::userHasPermission()}.
     *
     * @return bool Whether the rule permits the auth item it is associated with.
     */
    public function execute(
        string $userId,
        Item $item,
        RuleFactoryInterface $ruleFactory,
        array $parameters = [],
    ): bool;
}
