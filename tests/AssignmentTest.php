<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use PHPUnit\Framework\TestCase;
use Yiisoft\Rbac\Assignment;

final class AssignmentTest extends TestCase
{
    public function testImmutability(): void
    {
        $original = new Assignment('42', 'test1', 1_642_029_084);
        $new = $original->withItemName('test2');

        $this->assertNotSame($original, $new);
    }
}
