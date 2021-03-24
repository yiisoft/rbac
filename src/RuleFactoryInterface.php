<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

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
