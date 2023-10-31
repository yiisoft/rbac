<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Support;

use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\RuleContext;
use Yiisoft\Rbac\RuleInterface;

final class SubscriptionRule implements RuleInterface
{
    private const SUBSCRIPTION_MAP = [
        3 => true,
        4 => false,
    ];

    public function execute(?string $userId, Item $item, RuleContext $ruleContext): bool
    {
        if ($userId === null || $ruleContext->getParameterValue('voidSubscription') === true) {
            return false;
        }

        return self::SUBSCRIPTION_MAP[$userId] === true;
    }
}
