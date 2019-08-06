<?php
namespace Yiisoft\Rbac\Exceptions;

/**
 * InvalidArgumentException represents an exception caused by invalid arguments passed to a method.
 */
class InvalidArgumentException extends \BadMethodCallException implements ExceptionInterface
{
    /**
     * @return string the user-friendly name of this exception
     */
    public function getName()
    {
        return 'Invalid Argument';
    }
}
