<?php

namespace Yiisoft\Rbac\Tests;

use Yiisoft\Rbac\Rule;

class EasyRule extends Rule
{
    public function __construct()
    {
        parent::__construct(self::class);
    }
}
