<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\RuleInterface;

final class EasyRule implements RuleInterface
{
    private bool $expected;

    public function __construct(bool $expected = true)
    {
        $this->expected = $expected;
    }

    public function execute(string $userId, Item $item, array $parameters = []): bool
    {
        return $this->expected;
    }

    public function getName(): string
    {
        return self::class;
    }
}
