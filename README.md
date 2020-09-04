<p align="center">
    <a href="https://github.com/yiisoft" target="_blank">
        <img src="https://avatars0.githubusercontent.com/u/993323" height="100px">
    </a>
    <h1 align="center">Yii Role-Based Access Control Library</h1>
    <br>
</p>

This package provides [RBAC] (Role-Based Access Control) library.
It is used in [Yii Framework] but is supposed to be usable separately.

[RBAC]: https://en.wikipedia.org/wiki/Role-based_access_control
[Yii Framework]: https://yiiframework.com

[![Latest Stable Version](https://poser.pugx.org/yiisoft/rbac/v/stable.png)](https://packagist.org/packages/yiisoft/rbac)
[![Total Downloads](https://poser.pugx.org/yiisoft/rbac/downloads.png)](https://packagist.org/packages/yiisoft/rbac)
[![Code Coverage](https://scrutinizer-ci.com/g/yiisoft/rbac/badges/coverage.png)](https://scrutinizer-ci.com/g/yiisoft/rbac/)
[![Build Status](https://travis-ci.com/yiisoft/rbac.svg?branch=master)](https://travis-ci.com/yiisoft/rbac)


## Install:

```
composer require yiisoft/rbac
```

## Basic usage:

#### Сreate instance

```php
$manager = new Manager($storage, new ClassNameRuleFactory());
```
In the directory config will contain permissions and rules. 

#### Сreate permissions

```php

$manager->addPermission(new Permission('createPost'));
$manager->addPermission(new Permission('readPost'));
$manager->addPermission(new Permission('deletePost'));

```

After executing this code, this configuration will be saved in ../config/items.php

#### Create roles

```php
$manager->addRole(new Role('author'));
$manager->addRole(new Role('reader'));
```


#### Attach permissions to roles

```php
$manager->addChild(
    $storage->getRoleByName('reader'),
    $storage->getPermissionByName('readPost')
);

$manager->addChild(
    $storage->getRoleByName('author'),
    $storage->getPermissionByName('createPost')
);

$manager->addChild(
    $storage->getRoleByName('author'),
    $storage->getRoleByName('reader')
);
```

#### Assign role to user

```php
$userId = 100;
$manager->assign($storage->getRoleByName('author'), $userId);
```
After executing this code, this configuration will be saved in ../config/assignments.php


#### Check permissions

```php
if ($manager->userHasPermission($userId, 'createPost')) {
    echo 'author has permission createPost';
}
```

### Usage rules

```php

$manager->addRule(new ActionRule());
$manager->addPermission(
    (new Permission('viewList'))->withRuleName('action_rule')
);

```
The role will also support the rules.

#### Rule example 

```php
class ActionRule extends Rule
{
    public function __construct()
    {
        parent::__construct('action_rule');
    }

    public function execute(string $userId, Item $item, array $parameters = []): bool
    {
        return isset($parameters['action']) && $parameters['action'] === 'home';
    }
}
```

#### Check permissions with rule


```php
$anotherUserId = 103;
if (!$manager->userHasPermission($anotherUserId, 'viewList', ['action' => 'home'])) {
    echo 'reader not has permission index';
}
```

## Storage:

| Storage                                              | Description      |
| ---------------------------------------------------- |----------------- | 
| [PhpStorage](https://github.com/yiisoft/rbac-php)    | PHP file storage |
