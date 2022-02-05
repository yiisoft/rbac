<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

use Yiisoft\Rbac\Exception\RuleInterfaceNotImplementedException;
use Yiisoft\Rbac\Exception\RuleNotFoundException;

/**
 * Having a rule name creates an instance of it.
 */
interface RuleContainerInterface
{
    /**
     * @param string $name Rule name.
     *
     * @throws RuleNotFoundException
     * @throws RuleInterfaceNotImplementedException
     *
     * @return RuleInterface Rule created.
     */
    public function get(string $name): RuleInterface;
}
