<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use DateTime;
use PHPUnit\Framework\TestCase;
use Yiisoft\Rbac\Assignment;

final class AssignmentTest extends TestCase
{
    public function testImmutability(): void
    {
        $original = new Assignment('42', 'test1', new DateTime("2022-05-05 16:38:45"));
        $new = $original->withItemName('test2');

        $this->assertNotSame($original, $new);
    }
}
