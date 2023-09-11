<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use PHPUnit\Framework\TestCase;
use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\Role;

final class RoleTest extends TestCase
{
    public function testImmutability(): void
    {
        $original = new Role('test');
        $new1 = $original->withName('test2');
        $new2 = $original->withDescription('new description');
        $new3 = $original->withRuleName('test');

        $this->assertNotSame($original, $new1);
        $this->assertNotSame($original, $new2);
        $this->assertNotSame($original, $new3);
    }

    public function testDefaultAttributes(): void
    {
        $permission = new Role('test');
        $this->assertSame([
            'name' => 'test',
            'description' => '',
            'ruleName' => null,
            'type' => Item::TYPE_ROLE,
        ], $permission->getAttributes());
    }
}
