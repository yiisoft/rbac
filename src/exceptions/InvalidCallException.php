<?php
/**
 * @link http://www.yiiframework.com/
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license http://www.yiiframework.com/license/
 */

namespace yii\rbac\exceptions;

/**
 * InvalidCallException represents an exception caused by calling a method in a wrong way.
 *
 * @author Andrii Vasyliev <sol@hiqdev.com>
 * @since 3.0
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
