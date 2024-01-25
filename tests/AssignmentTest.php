<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use PHPUnit\Framework\TestCase;
use Yiisoft\Rbac\Assignment;

final class AssignmentTest extends TestCase
{
    public function testImmutability(): void
    {
        $original = new Assignment(userId: '42', itemName: 'test1', createdAt: 1_642_029_084);
        $new = $original->withItemName('test2');

        $this->assertNotSame($original, $new);
    }

    public function testGetAttributes(): void
    {
        $assignment = new Assignment(userId: '42', itemName: 'test1', createdAt: 1_642_029_084);
        $this->assertSame([
            'item_name' => 'test1',
            'user_id' => '42',
            'created_at' => 1_642_029_084,
        ], $assignment->getAttributes());
    }
}
