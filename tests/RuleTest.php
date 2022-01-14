<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use PHPUnit\Framework\TestCase;
use Yiisoft\Rbac\Tests\Support\AllowRule;

final class RuleTest extends TestCase
{
    public function testWithName(): void
    {
        $rule = new AllowRule('test');

        $this->assertSame('test', $rule->getName());
    }

    public function testWithoutName(): void
    {
        $rule = new AllowRule();

        $this->assertSame(AllowRule::class, $rule->getName());
    }
}
