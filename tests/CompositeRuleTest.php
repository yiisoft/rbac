<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Yiisoft\Rbac\CompositeRule;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\Tests\Support\EasyRule;
use Yiisoft\Rbac\Tests\Support\SimpleRuleFactory;

final class CompositeRuleTest extends TestCase
{
    public function compositeRuleDataProvider(): array
    {
        return [
            'AND empty' => [CompositeRule::AND, [], true],
            'AND all true' => [CompositeRule::AND, ['easy_rule_true', 'easy_rule_true'], true],
            'AND last false' => [CompositeRule::AND, ['easy_rule_true', 'easy_rule_false'], false],

            'OR empty' => [CompositeRule::OR, [], true],
            'OR all false' => [CompositeRule::OR, ['easy_rule_false', 'easy_rule_false'], false],
            'OR last true' => [CompositeRule::OR, ['easy_rule_false', 'easy_rule_true'], true],
        ];
    }

    /**
     * @dataProvider compositeRuleDataProvider
     */
    public function testCompositeRule(string $operator, array $rules, bool $expected): void
    {
        $rule = new CompositeRule($operator, $rules);
        $ruleFactory = new SimpleRuleFactory([
            'easy_rule_false' => new EasyRule(false),
            'easy_rule_true' => new EasyRule(true),
        ]);
        $result = $rule->execute('user', new Permission('permission'), $ruleFactory);
        $this->assertSame($expected, $result);
    }

    public function testInvalidOperator(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Operator could be either ' .
            CompositeRule::class .
            '::AND or ' .
            CompositeRule::class .
            '::OR, "no_such_operation" given.'
        );
        new CompositeRule('no_such_operation', []);
    }
}
