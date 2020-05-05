<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

class Permission extends Item
{
    public function getType(): string
    {
        return self::TYPE_PERMISSION;
    }

    public function canBeParentOfItem(Item $child): bool
    {
        return $child->getType() !== self::TYPE_ROLE;
    }
}
