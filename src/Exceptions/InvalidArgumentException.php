<?php

namespace Yiisoft\Rbac\Exceptions;

use Yiisoft\FriendlyException\FriendlyExceptionInterface;

/**
 * InvalidArgumentException represents an exception caused by invalid arguments passed to a method.
 */
class InvalidArgumentException extends \BadMethodCallException implements RbacExceptionInterface, FriendlyExceptionInterface
{
    /**
     * @return string the user-friendly name of this exception
     */
    public function getName(): string
    {
        return 'Invalid Argument';
    }

    public function getSolution(): ?string
    {
        return null;
    }
}
