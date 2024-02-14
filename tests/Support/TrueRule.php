<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Support;

use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\RuleContext;
use Yiisoft\Rbac\RuleInterface;

final class TrueRule implements RuleInterface
{
    public function execute(?string $userId, Item $item, RuleContext $ruleContext): bool
    {
        return true;
    }
}
