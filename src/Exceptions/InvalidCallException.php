<?php

namespace Yiisoft\Rbac\Exceptions;

/**
 * InvalidCallException represents an exception caused by calling a method in a wrong way.
 */
class InvalidCallException extends \Exception implements RbacExceptionInterface
{
    public function getName(): string
    {
        return 'Invalid Call';
    }
}
