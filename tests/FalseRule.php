<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\Rule;

class FalseRule extends Rule
{
    public function __construct()
    {
        parent::__construct('false');
    }

    public function execute(string $userId, Item $item, array $parameters = []): bool
    {
        return false;
    }
}
