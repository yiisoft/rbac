<?php
/**
 * @link http://www.yiiframework.com/
 *
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license http://www.yiiframework.com/license/
 */

namespace Yiisoft\Rbac\Exceptions;

/**
 * InvalidConfigException represents an exception caused by incorrect object configuration.
 *
 * @author Andrii Vasyliev <sol@hiqdev.com>
 *
 * @since 3.0
 */
class InvalidConfigException extends \Exception implements ExceptionInterface
{
    /**
     * @return string the user-friendly name of this exception
     */
    public function getName()
    {
        return 'Invalid Configuration';
    }
}
