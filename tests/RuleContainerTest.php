<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use PHPUnit\Framework\TestCase;
use stdClass;
use Yiisoft\Rbac\Exception\RuleInterfaceNotImplementedException;
use Yiisoft\Rbac\Exception\RuleNotFoundException;
use Yiisoft\Rbac\RuleContainer;
use Yiisoft\Rbac\RuleInterface;
use Yiisoft\Rbac\Tests\Support\AuthorRule;
use Yiisoft\Test\Support\Container\SimpleContainer;

final class RuleContainerTest extends TestCase
{
    public function testGet(): void
    {
        $ruleContainer = new RuleContainer(new SimpleContainer(), []);

        $rule = $ruleContainer->get(AuthorRule::class);

        $this->assertInstanceOf(AuthorRule::class, $rule);
    }

    public function testNotFound(): void
    {
        $ruleContainer = new RuleContainer(new SimpleContainer(), []);

        $this->expectException(RuleNotFoundException::class);
        $this->expectExceptionMessage('Rule "not-exists-rule" not found.');
        $ruleContainer->get('not-exists-rule');
    }

    public function testNotRuleInterface(): void
    {
        $ruleContainer = new RuleContainer(new SimpleContainer(), ['rule' => new stdClass()]);

        $this->expectException(RuleInterfaceNotImplementedException::class);
        $this->expectExceptionMessage('Rule "rule" should implement "' . RuleInterface::class . '".');
        $ruleContainer->get('rule');
    }
}
