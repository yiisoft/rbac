<?php
/**
 * @link http://www.yiiframework.com/
 *
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license http://www.yiiframework.com/license/
 */

return [
    \Yiisoft\Rbac\RuleFactoryInterface::class => [
        '__class' => \Yiisoft\Rbac\RuleFactory::class,
    ],
    \Yiisoft\Rbac\CheckAccessInterface::class => [
        '__class' => \Yiisoft\Rbac\DenyAll::class,
    ],
];
