<?php
/**
 * @link http://www.yiiframework.com/
 *
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license http://www.yiiframework.com/license/
 */

namespace Yiisoft\Rbac\Exceptions;

/**
 * InvalidValueException represents an exception caused by a function returning a value of unexpected type.
 *
 * @author Andrii Vasyliev <sol@hiqdev.com>
 *
 * @since 3.0
 */
class InvalidValueException extends \UnexpectedValueException implements ExceptionInterface
{
    /**
     * @return string the user-friendly name of this exception
     */
    public function getName()
    {
        return 'Invalid Return Value';
    }
}
