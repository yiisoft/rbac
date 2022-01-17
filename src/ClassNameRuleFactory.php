<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

use RuntimeException;
use Throwable;

use function get_class;

/**
 * Creates rule instance based on its class name.
 */
final class ClassNameRuleFactory implements RuleFactoryInterface
{
    public function create(string $name): RuleInterface
    {
        if (!class_exists($name)) {
            throw new RuntimeException(
                sprintf(
                    '%s supports creating rules by class name only, "%s" given.',
                    self::class,
                    $name
                )
            );
        }

        try {
            /** @psalm-suppress MixedMethodCall */
            $rule = new $name();
        } catch (Throwable $e) {
            throw new RuntimeException(
                sprintf('Can not instantiate rule "%s".', $name),
                0,
                $e
            );
        }

        if (!$rule instanceof RuleInterface) {
            throw new RuntimeException(
                sprintf(
                    'Rule "%s" must be an instance of %s.',
                    get_class($rule),
                    RuleInterface::class
                )
            );
        }

        return $rule;
    }
}
