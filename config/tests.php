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
        '__class' => \yii\cache\ArrayCache::class,
    ],
];
