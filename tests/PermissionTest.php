<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use DateTime;
use PHPUnit\Framework\TestCase;
use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\Permission;

final class PermissionTest extends TestCase
{
    public function testImmutability(): void
    {
        $now = new DateTime('2022-05-05 16:38:49');
        $original = new Permission('test');
        $new1 = $original->withName('test2');
        $new2 = $original->withDescription('new description');
        $new3 = $original->withUpdatedAt($now);
        $new4 = $original->withCreatedAt($now);
        $new5 = $original->withRuleName('test');

        $this->assertNotSame($original, $new1);
        $this->assertNotSame($original, $new2);
        $this->assertNotSame($original, $new3);
        $this->assertNotSame($original, $new4);
        $this->assertNotSame($original, $new5);
    }

    public function testDefaultAttributes(): void
    {
        $permission = new Permission('test');
        $this->assertSame([
            'name' => 'test',
            'description' => '',
            'ruleName' => null,
            'type' => Item::TYPE_PERMISSION,
            'updatedAt' => null,
            'createdAt' => null,
        ], $permission->getAttributes());
    }
}
