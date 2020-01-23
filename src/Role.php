<?php

namespace Yiisoft\Rbac;

class Role extends Item
{
    public function getType(): string
    {
        return self::TYPE_ROLE;
    }
}
