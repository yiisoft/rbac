<?php
namespace Yiisoft\Rbac\Exceptions;

/**
 * InvalidCallException represents an exception caused by calling a method in a wrong way.
 */
class InvalidCallException extends \BadMethodCallException implements ExceptionInterface
{
    /**
     * @return string the user-friendly name of this exception
     */
    public function getName()
    {
        return 'Invalid Call';
    }
}
