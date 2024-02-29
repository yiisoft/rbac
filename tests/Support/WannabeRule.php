<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Support;

use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\RuleContext;

final class WannabeRule
{
    public function execute(?string $userId, Item $item, RuleContext $context): bool
    {
        return true;
    }
}
