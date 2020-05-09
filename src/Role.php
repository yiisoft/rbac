<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

final class Role extends Item
{
    public function getType(): string
    {
        return self::TYPE_ROLE;
    }

    public function canBeParentOfItem(Item $child): bool
    {
        return true;
    }
}
