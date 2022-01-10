<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use Yiisoft\Rbac\Rule;

class TrueRule extends Rule
{
    public function __construct()
    {
        parent::__construct('true');
    }
}
