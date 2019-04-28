<?php

return [
    \Yiisoft\Rbac\BaseManager::class => [
        '__class' => \Yiisoft\Rbac\DbManager::class,
    ],
    'db' => [
        'dsn'      => '/tmp/rbac-test',
        'username' => 'rbac',
        'password' => 'rbac',
    ],
    'cache' => [
        '__class' => \Yiisoft\Cache\ArrayCache::class,
    ],
];
