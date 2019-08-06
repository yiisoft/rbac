<?php
return [
    \Yiisoft\Rbac\Factories\RuleFactoryInterface::class => [
        '__class' => \Yiisoft\Rbac\Factories\RuleFactory::class,
    ],
    \Yiisoft\Access\CheckAccessInterface::class => [
        '__class' => \Yiisoft\Rbac\DenyAll::class,
    ],
];
