<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Exception;

use Exception;
use Yiisoft\Rbac\RuleInterface;

final class RuleInterfaceNotImplementedException extends Exception
{
    public function __construct(string $name, int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct(
            sprintf(
                'Rule "%s" should implement "%s".',
                $name,
                RuleInterface::class,
            ),
            $code,
            $previous
        );
    }
}
