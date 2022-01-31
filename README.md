<p align="center">
    <a href="https://github.com/yiisoft" target="_blank">
        <img src="https://yiisoft.github.io/docs/images/yii_logo.svg" height="100px">
    </a>
    <h1 align="center">Yii Role-Based Access Control</h1>
    <br>
</p>

[![Latest Stable Version](https://poser.pugx.org/yiisoft/rbac/v/stable.png)](https://packagist.org/packages/yiisoft/rbac)
[![Total Downloads](https://poser.pugx.org/yiisoft/rbac/downloads.png)](https://packagist.org/packages/yiisoft/rbac)
[![Build status](https://github.com/yiisoft/rbac/workflows/build/badge.svg)](https://github.com/yiisoft/rbac/actions?query=workflow%3Abuild)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/yiisoft/rbac/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/yiisoft/rbac/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/yiisoft/rbac/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/yiisoft/rbac/?branch=master)
[![Mutation testing badge](https://img.shields.io/endpoint?style=flat&url=https%3A%2F%2Fbadge-api.stryker-mutator.io%2Fgithub.com%2Fyiisoft%2Frbac%2Fmaster)](https://dashboard.stryker-mutator.io/reports/github.com/yiisoft/rbac/master)
[![static analysis](https://github.com/yiisoft/rbac/workflows/static%20analysis/badge.svg)](https://github.com/yiisoft/rbac/actions?query=workflow%3A%22static+analysis%22)
[![type-coverage](https://shepherd.dev/github/yiisoft/rbac/coverage.svg)](https://shepherd.dev/github/yiisoft/rbac)

This package provides [RBAC](https://en.wikipedia.org/wiki/Role-based_access_control) (Role-Based Access Control)
library. It is used in [Yii Framework](https://yiiframework.com) but is usable separately as well.

## Features

- Flexible RBAC hierarchy with roles, permissions and rules.
- Role inheritance.
- Data could be passed to rules when checking access.
- Multiple storage adapters.
- Separate storages could be used for user-role assignments and role hierarchy.
- API to manage RBAC hierarchy.

## Requirements

- PHP 7.4 or higher.

## Installation

The package could be installed with composer:

```shell
composer require yiisoft/rbac --prefer-dist
```

One of the following storages should be installed as well:

- [PHP storage](https://github.com/yiisoft/rbac-php) - PHP file storage.
- [DB storage](https://github.com/yiisoft/rbac-db) - database storage based on 
  [yiisoft/db](https://github.com/yiisoft/db).

## General usage

### Setting up manager

First step when using RBAC is to configure an instance of `Manager`:

```php
/**
* @var \Yiisoft\Rbac\ItemsStorageInterface $rolesStorage
* @var \Yiisoft\Rbac\AssignmentsStorageInterface $assignmentsStorage
*/
$manager = new Manager($rolesStorage, $assignmentsStorage, new ClassNameRuleFactory());
```

It requires specifying roles storage (hierarchy itself) and assignment storage where user IDs are mapped to roles. Also,
rule factory is requires. Given a rule name stored in roles storage it can create an instance of `Rule`.

- Roles and permissions could usually be considered "semi-static", as they only change when you update your application
  code, so it may make sense to use PHP storage for it. 
- Assignments, on the other hand, could be considered "dynamic". They change more often: when creating a new user,
  or when updating user role from within your application. It may make sense to use database storage for assignments.

### Managing RBAC hierarchy

Before being able to check for permissions, a RBAC hierarchy should be defined. Usually it is done via either console
commands or migrations. Hierarchy consists of permissions, roles and rules:

- Permissions are granules of access such as "create a post" or "read a post".
- A role is what is assigned to the user. Role is granted one or more permissions. Typical roles are "manager" or
  "admin".
- Rule is a PHP class that given some data answers a single question "given the data, has the user the permission asked
  for".

In order to create permission, use the following code:

```php
$manager->addPermission(new Permission('createPost'));
$manager->addPermission(new Permission('readPost'));
$manager->addPermission(new Permission('deletePost'));
```

To add some roles:

```php
$manager->addRole(new Role('author'));
$manager->addRole(new Role('reader'));
```

Next, we need to attach permissions to roles:

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

Sometimes, basic permissions are not enough. In this case, rules are helpful. Rules are PHP classes that could be
added to permissions and roles. In this case, the role or permission is considered only when rule's `execute()` method
returns `true`.

```php
/** @var \Yiisoft\Rbac\Manager $manager */

$manager->addRule(new ActionRule());
$manager->addPermission(
    (new Permission('viewList'))->withRuleName('action_rule')
);

// or

$manager->addRule(new NewYearOnlyRule());
$manager->addRole(
    (new Role('NewYearMaintainer'))->withRuleName('new_year_only_rule')
);
```

The rule itself implementation is usually quite simple:

```php
use Yiisoft\Rbac\Rule;

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

In the above `$userId` that permission is checked by, `$item` is RBAC hierarchy item rule is attached to, and
`$parameters` is extra data supplied when checking for permission.

If you need to consider multiple rules at once, use composite rule:

```php
// Fresh and owned
$compositeRule = new CompositeRule('fresh_and_owned', CompositeRule::AND, [new FreshRule(), new OwnedRule()]);

// Fresh or owned
$compositeRule = new CompositeRule('fresh_and_owned', CompositeRule::OR, [new FreshRule(), new OwnedRule()]);
```

### Assigning roles to users

In order to assign a certain role to a user with a given ID, use the following code:

```php
$userId = 100;
$manager->assign($storage->getRoleByName('author'), $userId);
```

It could be done in an admin panel, via console command, or it could be built into the application business logic
itself.

### Check for permission

In order to check for permission, obtain an instance of `\Yiisoft\Access\AccessCheckerInterface` and use it:

```php
public function actionCreate(\Yiisoft\Access\AccessCheckerInterface $accessChecker): ResponseInterface
{
    $userId = getUserId();

    if ($accessChecker->userHasPermission($userId, 'createPost')) {
        // author has permission to create post
    }
}
```

Sometimes you need to add guest-only permission, which is not assigned to any user ID. In this case, you can specify
a role which is assigned to guest user:

```php
$manager->setGuestRole('guest');
$manager->addPermission(new Permission('signup'));
$manager->addRole(new Role('guest'));
$manager->addChild(
    $rolesStorage->getRoleByName('guest'), 
    $rolesStorage->getPermissionByName('signup')
);

$guestId = null;
if ($accessChecker->userHasPermission($guestId, 'signup')) {
    // Guest has "signup" permission.
}
```

If there is a rule involved, you may pass extra parameters:

```php
$anotherUserId = 103;
if (!$manager->userHasPermission($anotherUserId, 'viewList', ['action' => 'home'])) {
    echo 'reader not has permission index';
}
```

## Testing

### Unit testing

The package is tested with [PHPUnit](https://phpunit.de/). To run tests:

```shell
./vendor/bin/phpunit
```

### Mutation testing

The package tests are checked with [Infection](https://infection.github.io/) mutation framework with
[Infection Static Analysis Plugin](https://github.com/Roave/infection-static-analysis-plugin). To run it:

```shell
./vendor/bin/roave-infection-static-analysis-plugin
```

### Static analysis

The code is statically analyzed with [Psalm](https://psalm.dev/). To run static analysis:

```shell
./vendor/bin/psalm
```

## License

The Yii Dependency Injection is free software. It is released under the terms of the BSD License.
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
