<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

use InvalidArgumentException;

use function get_class;
use function gettype;
use function in_array;
use function is_object;

/**
 * Composite rule allows combining multiple rules.
 *
 * ```php
 * // Fresh and owned
 * $compositeRule = new CompositeRule('fresh_and_owned', CompositeRule::AND, [new FreshRule(), new OwnedRule()]);
 *
 * // Fresh or owned
 * $compositeRule = new CompositeRule('fresh_and_owned', CompositeRule::OR, [new FreshRule(), new OwnedRule()]);
 * ```
 */
final class CompositeRule implements RuleInterface
{
    public const AND = 'and';
    public const OR = 'or';

    private string $operator;

    /**
     * @var RuleInterface[]
     */
    private array $rules;

    /**
     * @param string $operator Operator to be used. Could be `CompositeRule::AND` or `CompositeRule::OR`.
     * @param RuleInterface[] $rules Array of rule instances.
     */
    public function __construct(string $operator, array $rules)
    {
        if (!in_array($operator, [self::AND, self::OR], true)) {
            throw new InvalidArgumentException(
                sprintf(
                    'Operator could be either %1$s::AND or %1$s::OR, "%2$s" given.',
                    self::class,
                    $operator
                )
            );
        }

        foreach ($rules as $rule) {
            if (!$rule instanceof RuleInterface) {
                /** @psalm-suppress RedundantConditionGivenDocblockType,DocblockTypeContradiction */
                $type = get_debug_type($rule);
                throw new InvalidArgumentException(
                    sprintf(
                        'Each rule should be an instance of %s, "%s" given.',
                        RuleInterface::class,
                        $type
                    )
                );
            }
        }

        $this->operator = $operator;
        $this->rules = $rules;
    }

    public function execute(string $userId, Item $item, array $parameters = []): bool
    {
        if (empty($this->rules)) {
            return true;
        }

        foreach ($this->rules as $rule) {
            $result = $rule->execute($userId, $item, $parameters);

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
