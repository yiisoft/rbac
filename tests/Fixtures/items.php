<?php

return [
    'Fast Metabolism' => [
        'name' => 'Fast Metabolism',
        'description' => 'Your metabolic rate is twice normal. This means that you are much less resistant to radiation and poison, but your body heals faster.',
        'type' => 'permission',
    ],
    'createPost' => [
        'name' => 'createPost',
        'description' => 'create a post',
        'type' => 'permission',
    ],
    'readPost' => [
        'name' => 'readPost',
        'description' => 'read a post',
        'type' => 'permission',
    ],
    'deletePost' => [
        'name' => 'deletePost',
        'description' => 'delete a post',
        'type' => 'permission',
    ],
    'updatePost' => [
        'name' => 'updatePost',
        'description' => 'update a post',
        'ruleName' => 'isAuthor',
        'type' => 'permission',
    ],
    'updateAnyPost' => [
        'name' => 'updateAnyPost',
        'description' => 'update any post',
        'type' => 'permission',
    ],
    'withoutChildren' => [
        'name' => 'withoutChildren',
        'type' => 'role',
    ],
    'reader' => [
        'name' => 'reader',
        'type' => 'role',
        'children' => [
            'readPost',
        ],
    ],
    'author' => [
        'name' => 'author',
        'type' => 'role',
        'children' => [
            'createPost',
            'updatePost',
            'reader',
        ],
    ],
    'admin' => [
        'name' => 'admin',
        'type' => 'role',
        'children' => [
            'author',
            'updateAnyPost',
        ],
    ],
];
