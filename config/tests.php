<?php

return [
    \yii\rbac\BaseManager::class => [
        '__class' => \yii\rbac\DbManager::class,
    ],
    'db' => [
        'dsn' => '/tmp/rbac-test',
        'username' => 'rbac',
        'password' => 'rbac',
    ],
    'cache' => [
        '__class' => \yii\cache\ArrayCache::class,
    ]
];
