<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Common;

use Yiisoft\Rbac\AssignmentsStorageInterface;
use Yiisoft\Rbac\ItemsStorageInterface;
use Yiisoft\Rbac\Manager;
use Yiisoft\Rbac\ManagerInterface;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\Role;
use Yiisoft\Rbac\RuleFactoryInterface;
use Yiisoft\Rbac\Tests\Support\AuthorRule;
use Yiisoft\Rbac\Tests\Support\EasyRule;
use Yiisoft\Rbac\Tests\Support\FakeAssignmentsStorage;
use Yiisoft\Rbac\Tests\Support\FakeItemsStorage;
use Yiisoft\Rbac\Tests\Support\SimpleRuleFactory;
use Yiisoft\Rbac\Tests\Support\SubscriptionRule;

trait ManagerConfigurationTestTrait
{
    protected function createManager(
        ?ItemsStorageInterface $itemsStorage = null,
        ?AssignmentsStorageInterface $assignmentsStorage = null,
        ?RuleFactoryInterface $ruleFactory = null,
        ?bool $enableDirectPermissions = false
    ): ManagerInterface {
        $arguments = [
            $itemsStorage ?? $this->createItemsStorage(),
            $assignmentsStorage ?? $this->createAssignmentsStorage(),
            $ruleFactory ?? new SimpleRuleFactory(),
        ];
        if ($enableDirectPermissions !== null) {
            $arguments[] = $enableDirectPermissions;
        }

        return new Manager(...$arguments);
    }

    protected function createItemsStorage(): ItemsStorageInterface
    {
        return new FakeItemsStorage();
    }

    protected function createAssignmentsStorage(): AssignmentsStorageInterface
    {
        return new FakeAssignmentsStorage();
    }

    protected function createFilledManager(): ManagerInterface
    {
        return $this
            ->createManager(
                $this->createItemsStorage(),
                $this->createAssignmentsStorage(),
                new SimpleRuleFactory([
                    'isAuthor' => new AuthorRule(),
                    'easyTrue' => new EasyRule(true),
                    'easyFalse' => new EasyRule(false),
                    'subscription' => new SubscriptionRule(),
                ]),
                enableDirectPermissions: true,
            )
            ->addPermission(new Permission('Fast Metabolism'))
            ->addPermission(new Permission('createPost'))
            ->addPermission(new Permission('publishPost'))
            ->addPermission(new Permission('readPost'))
            ->addPermission(new Permission('deletePost'))
            ->addPermission((new Permission('updatePost'))->withRuleName('isAuthor'))
            ->addPermission(new Permission('updateAnyPost'))
            ->addRole(new Role('reader'))
            ->addRole(new Role('author'))
            ->addRole(new Role('admin'))
            ->addRole(new Role('myDefaultRole'))
            ->setDefaultRoleNames(['myDefaultRole'])
            ->addChild('reader', 'readPost')
            ->addChild('author', 'createPost')
            ->addChild('author', 'updatePost')
            ->addChild('author', 'reader')
            ->addChild('admin', 'author')
            ->addChild('admin', 'updateAnyPost')
            ->assign(itemName: 'Fast Metabolism', userId: 'reader A')
            ->assign(itemName: 'reader', userId: 'reader A')
            ->assign(itemName: 'author', userId: 'author B')
            ->assign(itemName: 'deletePost', userId: 'author B')
            ->assign(itemName: 'publishPost', userId: 'author B')
            ->assign(itemName: 'admin', userId: 'admin C');
    }
}
