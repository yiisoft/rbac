<?php
return [
    \Yiisoft\Rbac\Factory\RuleFactoryInterface::class => [
        '__class' => \Yiisoft\Rbac\Factory\RuleFactory::class,
    ],
    \Yiisoft\Access\AccessCheckerInterface::class => [
        '__class' => \Yiisoft\Rbac\DenyAll::class,
    ],
];
