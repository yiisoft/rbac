<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

use InvalidArgumentException;

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
final class CompositeRule extends Rule
{
    public const AND = 'and';
    public const OR = 'or';

    private string $operator;

    /**
     * @var Rule[]
     */
    private array $rules;

    /**
     * @param string $name Rule name.
     * @param string $operator Operator to be used. Could be `CompositeRule::AND` or `CompositeRule::OR`.
     * @param Rule[] $rules Array of rule instances.
     * @psalm-param array $rules
     */
    public function __construct(string $name, string $operator, array $rules)
    {
        if (!in_array($operator, [self::AND, self::OR])) {
            throw new InvalidArgumentException(sprintf('Operator could be either \Yiisoft\Rbac\CompositeRule::AND or \Yiisoft\Rbac\CompositeRule::OR, "%s" given.', $operator));
        }

        foreach ($rules as $rule) {
            if (!$rule instanceof Rule) {
                $type = is_object($rule) ? get_class($rule) : gettype($rule);
                throw new InvalidArgumentException(sprintf('Each rule should be an instance of \Yiisoft\Rbac\Rule, "%s" given.', $type));
            }
        }

        parent::__construct($name);
        $this->operator = $operator;
        /** @var Rule[] $rules */
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

    public function getAttributes(): array
    {
        return [
            'name' => $this->getName(),
            'operator' => $this->operator,
            'rules' => $this->rules,
        ];
    }
}
