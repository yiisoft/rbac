<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

class Role extends Item
{
    public function getType(): string
    {
        return self::TYPE_ROLE;
    }
}
