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
     * @param string|null $userId The user ID. This should be a string representing the unique identifier of a user. For
     * guests the value is `null`.
     * @param Item $item The role or permission that this rule is associated with.
     * @param RuleContext $ruleContext Rule context.
     *
     * @return bool Whether the rule permits the auth item it is associated with.
     */
    public function execute(?string $userId, Item $item, RuleContext $ruleContext): bool;
}
