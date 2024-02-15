<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use PHPUnit\Framework\TestCase;
use Yiisoft\Rbac\RuleContext;
use Yiisoft\Rbac\SimpleRuleFactory;
use Yiisoft\Rbac\Tests\Support\TrueRule;

final class RuleContextTest extends TestCase
{
    public function testGetParameters(): void
    {
        $context = new RuleContext(new SimpleRuleFactory(), ['a' => 1, 'b' => 2]);
        $this->assertSame(['a' => 1, 'b' => 2], $context->getParameters());
    }

    public function testGetParameterValue(): void
    {
        $context = new RuleContext(new SimpleRuleFactory(), ['a' => 1, 'b' => 2]);
        $this->assertSame(1, $context->getParameterValue('a'));
        $this->assertNull($context->getParameterValue('c'));
    }

    public function testHasParameter(): void
    {
        $context = new RuleContext(new SimpleRuleFactory(), ['a' => 1, 'b' => 2]);
        $this->assertTrue($context->hasParameter('a'));
        $this->assertFalse($context->hasParameter('c'));
    }

    public function testCreateRule(): void
    {
        $context = new RuleContext(new SimpleRuleFactory(), ['a' => 1, 'b' => 2]);
        $this->assertEquals(new TrueRule(), $context->createRule(TrueRule::class));
    }
}
