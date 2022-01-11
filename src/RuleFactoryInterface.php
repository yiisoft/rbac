<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

/**
 * Having a rule name creates an instance of it.
 */
interface RuleFactoryInterface
{
    /**
     * @param string $name Class name or other rule definition.
     * @psalm-param class-string<Rule> $name
     *
     * @return Rule Rule created.
     */
    public function create(string $name): Rule;
}
