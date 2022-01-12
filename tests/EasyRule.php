<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\Rule;

class EasyRule extends Rule
{
    private bool $expected;

    public function __construct(bool $expected = true)
    {
        parent::__construct(self::class);
        $this->expected = $expected;
    }

    public function execute(string $userId, Item $item, array $parameters = []): bool
    {
        return $this->expected && parent::execute($userId, $item, $parameters);
    }
}
