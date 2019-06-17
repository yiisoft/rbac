<?php
/**
 * @link http://www.yiiframework.com/
 *
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license http://www.yiiframework.com/license/
 */

return [
    \Yiisoft\Rbac\Factories\RuleFactoryInterface::class => [
        '__class' => \Yiisoft\Rbac\Factories\RuleFactory::class,
    ],
    \Yiisoft\Access\CheckAccessInterface::class => [
        '__class' => \Yiisoft\Rbac\DenyAll::class,
    ],
];
