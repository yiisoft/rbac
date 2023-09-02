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

- PHP 8.0 or higher.

## Installation

The package is installed with composer:

```shell
composer require yiisoft/rbac
```

One of the following storages could be installed as well:

- [PHP storage](https://github.com/yiisoft/rbac-php) - PHP file storage;
- [DB storage](https://github.com/yiisoft/rbac-db) - database storage based on [Yii DB](https://github.com/yiisoft/db);
- [Cycle DB storage](https://github.com/yiisoft/rbac-cycle-db) - database storage based on 
  [Cycle DBAL](https://github.com/cycle/database).

Also, there is a rule factory implementation - [Rules Container](https://github.com/yiisoft/rbac-rules-container) (based 
on [Yii Factory](https://github.com/yiisoft/factory)).

All these can be replaced with custom implementations.

## General usage

### Setting up manager

First step when using RBAC is to configure an instance of `Manager`:

```php
use Yiisoft\Rbac\AssignmentsStorageInterface;
use Yiisoft\Rbac\ItemsStorageInterface;
use Yiisoft\Rbac\RuleFactoryInterface;

/**
* @var ItemsStorageInterface $itemsStorage
* @var AssignmentsStorageInterface $assignmentsStorage
* @var RuleFactoryInterface $ruleFactory
*/
$manager = new Manager($itemsStorage, $assignmentsStorage, $ruleFactory);
```

It requires specifying the following dependencies:

- Items storage (hierarchy itself).
- Assignments storage where user IDs are mapped to roles.
- Rule factory. Given a rule name stored in items storage it can create an instance of `Rule`.

Here are a few tips for choosing storage backend:

- Roles and permissions could usually be considered "semi-static", as they only change when you update your application
  code, so it may make sense to use PHP storage for it. 
- Assignments, on the other hand, could be considered "dynamic". They change more often: when creating a new user,
  or when updating user role from within your application. It may make sense to use database storage for assignments.

### Managing RBAC hierarchy

Before being able to check for permissions, a RBAC hierarchy must be defined. Usually it is done via either console
commands or migrations. Hierarchy consists of permissions, roles and rules:

- Permissions are granules of access such as "create a post" or "read a post".
- A role is what is assigned to the user. Role is granted one or more permissions. Typical roles are "manager" or
  "admin".
- Rule is a PHP class that given some data answers a single question "given the data, has the user the permission asked
  for".

In order to create a permission, use the following code:

```php
use Yiisoft\Rbac\ManagerInterface;
use Yiisoft\Rbac\Permission;

/** @var ManagerInterface $manager */
$manager->addPermission(new Permission('createPost'));
$manager->addPermission(new Permission('readPost'));
$manager->addPermission(new Permission('deletePost'));
```

To add some roles:

```php
use Yiisoft\Rbac\ManagerInterface;
use Yiisoft\Rbac\Role;

/** @var ManagerInterface $manager */
$manager->addRole(new Role('author'));
$manager->addRole(new Role('reader'));
```

Next, we need to attach permissions to roles:

```php
use Yiisoft\Rbac\ManagerInterface;

/** @var ManagerInterface $manager */
$manager->addChild('reader', 'readPost');
$manager->addChild('author', 'createPost');
$manager->addChild('author', 'deletePost');
$manager->addChild('author', 'reader');
```

Hierarchy for the example above:

```mermaid
flowchart LR
  createPost:::permission ---> author:::role
  readPost:::permission --> reader:::role --> author:::role
  deletePost:::permission ---> author:::role
  classDef permission fill:#fc0,stroke:#000,color:#000
  classDef role fill:#9c0,stroke:#000,color:#000
```

Sometimes, basic permissions are not enough. In this case, rules are helpful. Rules are PHP classes that could be
added to permissions and roles:

```php
use Yiisoft\Rbac\RuleInterface;

class ActionRule implements RuleInterface
{
    public function execute(string $userId, Item $item, array $parameters = []): bool
    {
        return isset($parameters['action']) && $parameters['action'] === 'home';
    }
}
```

With rule added, the role or permission is considered only when rule's `execute()` method returns `true`.

The parameters are:

- `$userId` is user id to check permission against;
- `$item` is RBAC hierarchy item that rule is attached to;
- `$parameters` is extra data supplied when checking for permission.

To use rules with `Manager`, specify their names with added permissions or roles:

```php
use Yiisoft\Rbac\ManagerInterface;
use Yiisoft\Rbac\Permission;

/** @var ManagerInterface $manager */
$manager->addPermission( 
    (new Permission('viewList'))->withRuleName('action_rule'),
);

// or

$manager->addRole(
    (new Role('NewYearMaintainer'))->withRuleName('new_year_only_rule')
);
```

The rule names `action_rule` and `new_year_only_rule` are resolved to `ActionRule` and `NewYearOnlyRule` class instances
accordingly via rule factory.

If you need to aggregate multiple rules at once, use composite rule:

```php
use Yiisoft\Rbac\CompositeRule;

// Fresh and owned
$compositeRule = new CompositeRule(CompositeRule::AND, [new FreshRule(), new OwnedRule()]);

// Fresh or owned
$compositeRule = new CompositeRule(CompositeRule::OR, [new FreshRule(), new OwnedRule()]);
```

### Assigning roles to users

In order to assign a certain role to a user with a given ID, use the following code:

```php
use Yiisoft\Rbac\ManagerInterface;

/** @var ManagerInterface $manager */
$userId = 100;
$manager->assign('author', $userId);
```

It could be done in an admin panel, via console command, or it could be built into the application business logic 
itself.

### Check for permission

In order to check for permission, obtain an instance of `Yiisoft\Access\AccessCheckerInterface` and use it:

```php
use Psr\Http\Message\ResponseInterface; 
use Yiisoft\Access\AccessCheckerInterface;

public function actionCreate(AccessCheckerInterface $accessChecker): ResponseInterface
{
    $userId = getUserId();

    if ($accessChecker->userHasPermission($userId, 'createPost')) {
        // author has permission to create post
    }
}
```

Sometimes you need to add guest-only permission, which is not assigned to any user ID. In this case, you can specify a 
role which is assigned to guest user:

```php
use Yiisoft\Access\AccessCheckerInterface;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\Role;

/** 
 * @var ManagerInterface $manager
 * @var AccessCheckerInterface $accessChecker 
 */
$manager->setGuestRoleName('guest');
$manager->addPermission(new Permission('signup'));
$manager->addRole(new Role('guest'));
$manager->addChild('guest', 'signup');

$guestId = null;
if ($accessChecker->userHasPermission($guestId, 'signup')) {
    // Guest has "signup" permission.
}
```

If there is a rule involved, you may pass extra parameters:

```php
use Yiisoft\Rbac\ManagerInterface;

/** @var ManagerInterface $manager */
$anotherUserId = 103;
if (!$manager->userHasPermission($anotherUserId, 'viewList', ['action' => 'home'])) {
    echo 'reader hasn\'t "index" permission';
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
