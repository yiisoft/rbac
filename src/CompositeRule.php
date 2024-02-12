<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

use InvalidArgumentException;

use function in_array;

/**
 * Composite rule allows combining multiple rules.
 *
 * ```php
 * // Fresh and owned
 * $compositeRule = new CompositeRule(CompositeRule::AND, [FreshRule::class, OwnedRule::class]);
 *
 * // Fresh or owned
 * $compositeRule = new CompositeRule(CompositeRule::OR, [FreshRule::class, OwnedRule::class]);
 * ```
 */
final class CompositeRule implements RuleInterface
{
    public const AND = 'and';
    public const OR = 'or';

    /**
     * @param string $operator Operator to be used. Could be `CompositeRule::AND` or `CompositeRule::OR`.
     * @param string[] $ruleNames Array of rule names.
     */
    public function __construct(
        private readonly string $operator,
        private readonly array $ruleNames,
    ) {
        if (!in_array($operator, [self::AND, self::OR], true)) {
            throw new InvalidArgumentException(
                sprintf(
                    'Operator could be either %1$s::AND or %1$s::OR, "%2$s" given.',
                    self::class,
                    $operator
                )
            );
        }
    }

    public function execute(?string $userId, Item $item, RuleContext $ruleContext): bool
    {
        if (empty($this->ruleNames)) {
            return true;
        }

        foreach ($this->ruleNames as $ruleName) {
            $result = $ruleContext->createRule($ruleName)->execute($userId, $item, $ruleContext);

            if ($this->operator === self::AND && $result === false) {
                return false;
            }

            if ($this->operator === self::OR && $result === true) {
                return true;
            }
        }

        return $this->operator === self::AND;
    }
}
