<?php
/**
 * @link http://www.yiiframework.com/
 *
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license http://www.yiiframework.com/license/
 */

namespace yii\rbac;

/**
 * BaseItem with constructor that sets properties by given array.
 *
 * @author Andrii Vasyliev <sol@hiqdev.com>
 *
 * @since 3.0
 */
abstract class BaseItem
{
    public function __construct(array $values = [])
    {
        foreach ($values as $key => $value) {
            $this->{$key} = $value;
        }
    }
}
