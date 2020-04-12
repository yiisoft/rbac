<?php

namespace Yiisoft\Rbac\Exceptions;

/**
 * InvalidArgumentException represents an exception caused by invalid arguments passed to a method.
 */
class InvalidArgumentException extends \InvalidArgumentException implements RbacExceptionInterface
{
    /**
     * @return string the user-friendly name of this exception
     */
    public function getName(): string
    {
        return 'Invalid Argument';
    }
}
