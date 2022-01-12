<?php

namespace Yiisoft\Rbac\Tests;

use PHPUnit\Framework\TestCase;
use Yiisoft\Rbac\Permission;

final class PermissionTest extends TestCase
{
    public function testImmutability(): void
    {
        $original = new Permission('test');
        $new1 = $original->withName('test2');
        $new2 = $original->withDescription('new description');
        $new3 = $original->withUpdatedAt(1642029084);
        $new4 = $original->withCreatedAt(1642029084);
        $new5 = $original->withRuleName('test');

        $this->assertNotSame($original, $new1);
        $this->assertNotSame($original, $new2);
        $this->assertNotSame($original, $new3);
        $this->assertNotSame($original, $new4);
        $this->assertNotSame($original, $new5);
    }
}
