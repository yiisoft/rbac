<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Support;

use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\RuleContext;
use Yiisoft\Rbac\RuleInterface;

final class SubscriptionRule implements RuleInterface
{
    private const SUBSCRIPTION_MAP = [
        '3' => true,
        '4' => false,
    ];

    public function execute(?string $userId, Item $item, RuleContext $context): bool
    {
        if ($userId === null || $context->getParameterValue('voidSubscription') === true) {
            return false;
        }

        return self::SUBSCRIPTION_MAP[$userId] ?? null === true;
    }
}
