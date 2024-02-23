<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use PHPUnit\Framework\TestCase;
use Yiisoft\Rbac\Exception\RuleInterfaceNotImplementedException;
use Yiisoft\Rbac\Exception\RuleNotFoundException;
use Yiisoft\Rbac\RuleInterface;
use Yiisoft\Rbac\SimpleRuleFactory;
use Yiisoft\Rbac\Tests\Support\TrueRule;
use Yiisoft\Rbac\Tests\Support\WannabeRule;

final class SimpleRuleFactoryTest extends TestCase
{
    public function testCreate(): void
    {
        $this->assertEquals(new TrueRule(), (new SimpleRuleFactory())->create(TrueRule::class));
    }

    public function testCreateWithNonExistingRule(): void
    {
        $this->expectException(RuleNotFoundException::class);
        $this->expectExceptionMessage('Rule "non-existing-rule" not found.');
        (new SimpleRuleFactory())->create('non-existing-rule');
    }

    public function testCreateWithRuleMissingImplements(): void
    {
        $className = WannabeRule::class;
        $interfaceName = RuleInterface::class;

        $this->expectException(RuleInterfaceNotImplementedException::class);
        $this->expectExceptionMessage("Rule \"$className\" must implement \"$interfaceName\".");
        (new SimpleRuleFactory())->create($className);
    }
}
