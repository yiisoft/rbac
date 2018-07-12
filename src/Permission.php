<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

final class Permission extends Item
{
    public function getType(): string
    {
        return self::TYPE_PERMISSION;
    }
}
