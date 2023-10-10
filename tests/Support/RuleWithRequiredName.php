<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Support;

use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\RuleInterface;

final class RuleWithRequiredName implements RuleInterface
{
    public function __construct(private string $name)
    {
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function execute(?string $userId, Item $item, array $parameters = []): bool
    {
        return true;
    }
}
