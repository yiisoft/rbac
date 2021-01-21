<p align="center">
    <a href="https://github.com/yiisoft" target="_blank">
        <img src="https://yiisoft.github.io/docs/images/yii_logo.svg" height="100px">
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
[![Build status](https://github.com/yiisoft/rbac/workflows/build/badge.svg)](https://github.com/yiisoft/rbac/actions?query=workflow%3Abuild)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/yiisoft/rbac/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/yiisoft/rbac/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/yiisoft/rbac/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/yiisoft/rbac/?branch=master)
[![Mutation testing badge](https://img.shields.io/endpoint?style=flat&url=https%3A%2F%2Fbadge-api.stryker-mutator.io%2Fgithub.com%2Fyiisoft%2Frbac%2Fmaster)](https://dashboard.stryker-mutator.io/reports/github.com/yiisoft/rbac/master)
[![static analysis](https://github.com/yiisoft/rbac/workflows/static%20analysis/badge.svg)](https://github.com/yiisoft/rbac/actions?query=workflow%3A%22static+analysis%22)
[![type-coverage](https://shepherd.dev/github/yiisoft/rbac/coverage.svg)](https://shepherd.dev/github/yiisoft/rbac)


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

### Unit testing

The package is tested with [PHPUnit](https://phpunit.de/). To run tests:

```shell
./vendor/bin/phpunit
```

### Mutation testing

The package tests are checked with [Infection](https://infection.github.io/) mutation framework. To run it:

```shell
./vendor/bin/infection
```

### Static analysis

The code is statically analyzed with [Psalm](https://psalm.dev/). To run static analysis:

```shell
./vendor/bin/psalm
```

## License

The Yii Role-Based Access Control Library is free software. It is released under the terms of the BSD License.
Please see [`LICENSE`](./LICENSE.md) for more information.

Maintained by [Yii Software](https://www.yiiframework.com/).

## Support the project

[![Open Collective](https://img.shields.io/badge/Open%20Collective-sponsor-7eadf1?logo=open%20collective&logoColor=7eadf1&labelColor=555555)](https://opencollective.com/yiisoft)

## Follow updates

[![Official website](https://img.shields.io/badge/Powered_by-Yii_Framework-green.svg?style=flat)](https://www.yiiframework.com/)
[![Twitter](https://img.shields.io/badge/twitter-follow-1DA1F2?logo=twitter&logoColor=1DA1F2&labelColor=555555?style=flat)](https://twitter.com/yiiframework)
[![Telegram](https://img.shields.io/badge/telegram-join-1DA1F2?style=flat&logo=telegram)](https://t.me/yii3en)
[![Facebook](https://img.shields.io/badge/facebook-join-1DA1F2?style=flat&logo=facebook&logoColor=ffffff)](https://www.facebook.com/groups/yiitalk)
[![Slack](https://img.shields.io/badge/slack-join-1DA1F2?style=flat&logo=slack)](https://yiiframework.com/go/slack)
