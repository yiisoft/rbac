<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Yiisoft\Rbac\CompositeRule;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\RuleContext;
use Yiisoft\Rbac\SimpleRuleFactory;
use Yiisoft\Rbac\Tests\Support\FalseRule;
use Yiisoft\Rbac\Tests\Support\TrueRule;

final class CompositeRuleTest extends TestCase
{
    public static function dataCompositeRule(): array
    {
        return [
            'AND empty' => [CompositeRule::AND, [], true],
            'AND all true' => [CompositeRule::AND, [TrueRule::class, TrueRule::class], true],
            'AND last false' => [CompositeRule::AND, [TrueRule::class, FalseRule::class], false],

            'OR empty' => [CompositeRule::OR, [], true],
            'OR all false' => [CompositeRule::OR, [FalseRule::class, FalseRule::class], false],
            'OR last true' => [CompositeRule::OR, [FalseRule::class, TrueRule::class], true],
        ];
    }

    /**
     * @dataProvider dataCompositeRule
     */
    public function testCompositeRule(string $operator, array $rules, bool $expected): void
    {
        $rule = new CompositeRule($operator, $rules);
        $result = $rule->execute('user', new Permission('permission'), new RuleContext(new SimpleRuleFactory(), []));
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
