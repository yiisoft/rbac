<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Exception;

use Exception;
use Throwable;

final class RuleNotFoundException extends Exception
{
    public function __construct(string $name, int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct("Rule \"$name\" not found.", $code, $previous);
    }
}
