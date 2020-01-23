<?php

namespace Yiisoft\Rbac\Exceptions;

use Yiisoft\FriendlyException\FriendlyExceptionInterface;

/**
 * InvalidCallException represents an exception caused by calling a method in a wrong way.
 */
class InvalidCallException extends \BadMethodCallException implements RbacExceptionInterface, FriendlyExceptionInterface
{
    public function getName(): string
    {
        return 'Invalid Call';
    }

    public function getSolution(): ?string
    {
        return null;
    }
}
