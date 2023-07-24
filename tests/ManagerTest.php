<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use PHPUnit\Framework\TestCase;
use Yiisoft\Rbac\Tests\Common\ManagerTestConfigurationTrait;
use Yiisoft\Rbac\Tests\Common\ManagerTestLogicTrait;

final class ManagerTest extends TestCase
{
    use ManagerTestConfigurationTrait;
    use ManagerTestLogicTrait;
}
