<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Support;

use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\Rule;

final class AllowRule extends Rule
{
    public function execute(string $userId, Item $item, array $parameters = []): bool
    {
        return true;
    }
}
