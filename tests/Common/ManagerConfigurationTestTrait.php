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

trait ManagerConfigurationTestTrait
{
    protected ItemsStorageInterface $itemsStorage;
    protected AssignmentsStorageInterface $assignmentsStorage;

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

    protected function createFilledManager(bool $enableDirectPermissions = false): ManagerInterface
    {
        $this->itemsStorage = $this->createFilledItemsStorage();
        $this->assignmentsStorage = $this->createFilledAssignmentsStorage();

        $manager = $this->createManager(
            $this->itemsStorage,
            $this->assignmentsStorage,
            new SimpleRuleFactory([
                'isAuthor' => new AuthorRule(),
                'easyTrue' => new EasyRule(false),
                'easyFalse' => new EasyRule(false),
            ]),
            $enableDirectPermissions,
        );
        $manager->setDefaultRoleNames(['myDefaultRole']);

        return $manager;
    }

    private function createFilledItemsStorage(): ItemsStorageInterface
    {
        $storage = $this->createItemsStorage();

        $storage->add(new Permission('Fast Metabolism'));
        $storage->add(new Permission('createPost'));
        $storage->add(new Permission('publishPost'));
        $storage->add(new Permission('readPost'));
        $storage->add(new Permission('deletePost'));
        $storage->add((new Permission('updatePost'))->withRuleName('isAuthor'));
        $storage->add(new Permission('updateAnyPost'));
        $storage->add(new Role('withoutChildren'));
        $storage->add(new Role('reader'));
        $storage->add(new Role('author'));
        $storage->add(new Role('admin'));
        $storage->add(new Role('myDefaultRole'));

        $storage->addChild('reader', 'readPost');
        $storage->addChild('author', 'createPost');
        $storage->addChild('author', 'updatePost');
        $storage->addChild('author', 'reader');
        $storage->addChild('admin', 'author');
        $storage->addChild('admin', 'updateAnyPost');

        return $storage;
    }

    private function createFilledAssignmentsStorage(): AssignmentsStorageInterface
    {
        $storage = $this->createAssignmentsStorage();

        $storage->add('Fast Metabolism', 'reader A');
        $storage->add('reader', 'reader A');
        $storage->add('author', 'author B');
        $storage->add('deletePost', 'author B');
        $storage->add('publishPost', 'author B');
        $storage->add('admin', 'admin C');

        return $storage;
    }
}
