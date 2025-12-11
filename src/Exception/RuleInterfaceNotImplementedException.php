<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Exception;

use Exception;
use Throwable;
use Yiisoft\Rbac\RuleInterface;

final class RuleInterfaceNotImplementedException extends Exception
{
    public function __construct(string $name, int $code = 0, ?Throwable $previous = null)
    {
        $interfaceName = RuleInterface::class;

        parent::__construct(
            "Rule \"$name\" must implement \"$interfaceName\".",
            $code,
            $previous,
        );
    }
}
