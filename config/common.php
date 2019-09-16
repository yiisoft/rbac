<?php
return [
    \Yiisoft\Rbac\RuleFactoryInterface::class => [
        '__class' => \Yiisoft\Rbac\RuleFactory::class,
    ],
    \Yiisoft\Access\AccessCheckerInterface::class => [
        '__class' => \Yiisoft\Rbac\DenyAll::class,
    ],
];
