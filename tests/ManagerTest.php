<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use PHPUnit\Framework\TestCase;
use Yiisoft\Rbac\Tests\Common\ManagerConfigurationTestTrait;
use Yiisoft\Rbac\Tests\Common\ManagerLogicTestTrait;

final class ManagerTest extends TestCase
{
    use ManagerConfigurationTestTrait;
    use ManagerLogicTestTrait;
}
