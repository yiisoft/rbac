<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Exception;

use RuntimeException;
use Throwable;
use Yiisoft\Rbac\Item;

final class ItemAlreadyExistsException extends RuntimeException
{
    public function __construct(Item $item, int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct(
            "Role or permission with name \"{$item->getName()}\" already exists.",
            $code,
            $previous,
        );
    }
}
