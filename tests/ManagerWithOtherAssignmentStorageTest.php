<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use PHPUnit\Framework\TestCase;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\Role;
use Yiisoft\Rbac\StorageInterface;

/**
 * @group rbac
 */
final class ManagerWithOtherAssignmentStorageTest extends ManagerTest
{
    protected StorageInterface $assignmentStorage;

    protected function setUp(): void
    {
        parent::setUp();
        $this->storage = $this->createStorage();
        $this->assignmentStorage = $this->createAssignmentStorage();
        $this->manager = $this->createManager($this->storage);
        $this->manager->setAssignmentStorage($this->assignmentStorage);
    }

    public function testRevokeRole(): void
    {
        $storage = $this->storage;
        $assignmentStorage = $this->assignmentStorage;
        $manager = $this->manager;

        $manager->revoke(
            $storage->getRoleByName('reader'),
            'reader A'
        );

        $this->assertEquals(['Fast Metabolism'], array_keys($assignmentStorage->getUserAssignments('reader A')));
        $this->assertNotEquals(['Fast Metabolism'], array_keys($storage->getUserAssignments('reader A')));
    }

    public function testRevokePermission(): void
    {
        $storage = $this->storage;
        $assignmentStorage = $this->assignmentStorage;
        $manager = $this->manager;

        $manager->revoke(
            $storage->getPermissionByName('deletePost'),
            'author B'
        );

        $this->assertEquals(['author'], array_keys($assignmentStorage->getUserAssignments('author B')));
        $this->assertNotEquals(['author'], array_keys($storage->getUserAssignments('author B')));
    }

    public function testRevokeAll(): void
    {
        $assignmentStorage = $this->assignmentStorage;
        $manager = $this->manager;

        $manager->revokeAll('author B');
        $this->assertEmpty($assignmentStorage->getUserAssignments('author B'));
    }

    protected function createStorage(): StorageInterface
    {
        $storage = new FakeStorage();

        $storage->addItem(new Permission('Fast Metabolism'));
        $storage->addItem(new Permission('createPost'));
        $storage->addItem(new Permission('readPost'));
        $storage->addItem(new Permission('deletePost'));
        $storage->addItem((new Permission('updatePost'))->withRuleName('isAuthor'));
        $storage->addItem(new Permission('updateAnyPost'));
        $storage->addItem(new Role('withoutChildren'));
        $storage->addItem(new Role('reader'));
        $storage->addItem(new Role('author'));
        $storage->addItem(new Role('admin'));

        $storage->addChild(new Role('reader'), new Permission('readPost'));
        $storage->addChild(new Role('author'), new Permission('createPost'));
        $storage->addChild(new Role('author'), new Permission('updatePost'));
        $storage->addChild(new Role('author'), new Role('reader'));
        $storage->addChild(new Role('admin'), new Role('author'));
        $storage->addChild(new Role('admin'), new Permission('updateAnyPost'));

        $storage->addRule(new AuthorRule('isAuthor'));

        return $storage;
    }

    protected function createAssignmentStorage(): StorageInterface
    {
        $storage = new FakeStorage();

        $storage->addAssignment('reader A', new Permission('Fast Metabolism'));
        $storage->addAssignment('reader A', new Role('reader'));
        $storage->addAssignment('author B', new Role('author'));
        $storage->addAssignment('author B', new Permission('deletePost'));
        $storage->addAssignment('admin C', new Role('admin'));

        return $storage;
    }
}
