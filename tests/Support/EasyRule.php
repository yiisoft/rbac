<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Support;

use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\RuleInterface;

final class EasyRule implements RuleInterface
{
    public function __construct(private bool $expected = true)
    {
    }

    public function execute(?string $userId, Item $item, array $parameters = []): bool
    {
        return $this->expected;
    }

    public function getName(): string
    {
        return self::class;
    }
}
