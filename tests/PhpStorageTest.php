<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use PHPUnit\Framework\TestCase;
use Yiisoft\Files\FileHelper;
use Yiisoft\Rbac\Assignment;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\PhpStorage;
use Yiisoft\Rbac\Role;

/**
 * @group rbac
 */
final class PhpStorageTest extends TestCase
{
    private const STUB_DIRECTORY = '/Stub/';
    private string $testDataPath;

    public function testGetItems(): void
    {
        $items = $this->createStorage()->getItems();
        $this->assertCount(10, $items);
        $this->assertEquals(
            [
                'Fast Metabolism',
                'createPost',
                'readPost',
                'deletePost',
                'updatePost',
                'updateAnyPost',
                'withoutChildren',
                'reader',
                'author',
                'admin',
            ],
            array_keys($items)
        );
    }

    public function testClear(): void
    {
        $storage = $this->createStorage();
        $storage->clear();

        $storage = $this->createStorage();

        $this->assertCount(0, $storage->getItems());
        $this->assertCount(0, $storage->getChildren());
        $this->assertCount(0, $storage->getRules());
        $this->assertCount(0, $storage->getAssignments());
    }

    public function testClearRoles(): void
    {
        $storage = $this->createStorage();
        $storage->clearRoles();
        $this->assertCount(6, $this->createStorage()->getItems());
    }

    public function testClearAssignments(): void
    {
        $storage = $this->createStorage();
        $storage->clearAssignments();
        $this->assertCount(0, $this->createStorage()->getAssignments());
    }

    public function testClearPermissions(): void
    {
        $storage = $this->createStorage();
        $storage->clearPermissions();

        $storage = $this->createStorage();
        $this->assertCount(0, $storage->getPermissions());
        $this->assertCount(4, $storage->getItems());
    }

    public function testClearRules(): void
    {
        $storage = $this->createStorage();
        $storage->clearRules();

        $storage = $this->createStorage();
        $this->assertCount(0, $storage->getRules());
    }

    public function testGetPermissionItemByName(): void
    {
        $storage = $this->createStorage();

        $this->assertInstanceOf(Permission::class, $storage->getItemByName('createPost'));
        $this->assertNull($storage->getItemByName('nonExistPermission'));
    }

    public function testGetRoleItemByName(): void
    {
        $storage = $this->createStorage();

        $this->assertInstanceOf(Role::class, $storage->getItemByName('reader'));
        $this->assertNull($storage->getItemByName('nonExistRole'));
    }

    public function testAddPermissionItem(): void
    {
        $storage = $this->createStorage();

        $item = new Permission('testAddedPermission');
        $storage->addItem($item);

        $this->assertCount(11, $storage->getItems());
        $this->assertNotNull($storage->getPermissionByName('testAddedPermission'));
    }

    public function testAddRoleItem(): void
    {
        $storage = $this->createStorage();

        $item = new Role('testAddedRole');
        $storage->addItem($item);

        $this->assertCount(11, $storage->getItems());
        $this->assertNotNull($storage->getRoleByName('testAddedRole'));
    }

    public function testGetRoleByName(): void
    {
        $storage = $this->createStorage();

        $this->assertInstanceOf(Role::class, $storage->getRoleByName('reader'));
        $this->assertNull($storage->getRoleByName('nonExistRole'));
    }

    public function testGetRoles(): void
    {
        $storage = $this->createStorage();

        $this->assertEquals(
            [
                'withoutChildren',
                'reader',
                'author',
                'admin',
            ],
            array_keys($storage->getRoles())
        );
    }

    public function testGetPermissionByName(): void
    {
        $storage = $this->createStorage();

        $this->assertInstanceOf(Permission::class, $storage->getPermissionByName('readPost'));
        $this->assertNull($storage->getPermissionByName('nonExistPermission'));
    }

    public function testGetPermissions(): void
    {
        $storage = $this->createStorage();

        $this->assertEquals(
            [
                'Fast Metabolism',
                'createPost',
                'readPost',
                'deletePost',
                'updatePost',
                'updateAnyPost',
            ],
            array_keys($storage->getPermissions())
        );
    }

    public function testGetChildren(): void
    {
        $children = $this->createStorage()->getChildren();

        $this->assertEquals(['readPost'], array_keys($children['reader']));
        $this->assertEquals(
            [
                'createPost',
                'updatePost',
                'reader'
            ],
            array_keys($children['author'])
        );
        $this->assertEquals(
            [
                'author',
                'updateAnyPost'
            ],
            array_keys($children['admin'])
        );
    }

    public function testGetChildrenByName(): void
    {
        $storage = $this->createStorage();
        $this->assertEquals(
            [
                'createPost',
                'updatePost',
                'reader'
            ],
            array_keys($storage->getChildrenByName('author'))
        );
        $this->assertEmpty($storage->getChildrenByName('itemNotExist'));
    }

    public function testGetAssignments(): void
    {
        $storage = $this->createStorage();
        $this->assertEquals(
            [
                'reader A',
                'author B',
                'admin C'
            ],
            array_keys($storage->getAssignments())
        );
    }

    public function testGetUserAssignments(): void
    {
        $storage = $this->createStorage();
        $this->assertEquals(
            [
                'author',
                'deletePost'
            ],
            array_keys($storage->getUserAssignments('author B'))
        );
        $this->assertEmpty($storage->getUserAssignments('unknown user'));
    }

    public function testGetUserAssignmentByName(): void
    {
        $storage = $this->createStorage();
        $this->assertInstanceOf(
            Assignment::class,
            $storage->getUserAssignmentByName('author B', 'author')
        );

        $this->assertNull($storage->getUserAssignmentByName('author B', 'nonExistAssigment'));
    }

    public function testGetRules(): void
    {
        $storage = $this->createStorage();
        $this->assertEquals(['isAuthor'], array_keys($storage->getRules()));
    }

    public function testGetRuleByName(): void
    {
        $storage = $this->createStorage();

        $this->assertInstanceOf(AuthorRule::class, $storage->getRuleByName('isAuthor'));
        $this->assertNull($storage->getRuleByName('nonExistRule'));
    }

    public function testAddChild(): void
    {
        $storage = $this->createStorage();
        $role = $storage->getRoleByName('reader');
        $permission = $storage->getPermissionByName('createPost');

        $storage->addChild($role, $permission);
        $this->assertEquals(
            [
                'readPost',
                'createPost'
            ],
            array_keys($storage->getChildrenByName('reader'))
        );
    }

    public function testHasChildren(): void
    {
        $storage = $this->createStorage();
        $this->assertTrue($storage->hasChildren('reader'));
        $this->assertFalse($storage->hasChildren('withoutChildren'));
        $this->assertFalse($storage->hasChildren('nonExistChildren'));
    }

    public function testRemoveChild(): void
    {
        $storage = $this->createStorage();
        $role = $storage->getRoleByName('reader');
        $permission = $storage->getPermissionByName('readPost');

        $storage->removeChild($role, $permission);
        $this->assertEmpty($storage->getChildrenByName('reader'));
    }

    public function testRemoveChildren(): void
    {
        $storage = $this->createStorage();
        $role = $storage->getRoleByName('reader');

        $storage->removeChildren($role);
        $this->assertEmpty($storage->getChildrenByName('reader'));
    }

    public function testAddAssignment(): void
    {
        $storage = $this->createStorage();
        $role = $storage->getRoleByName('author');

        $storage->addAssignment('reader A', $role);
        $this->assertEquals(
            [
                'Fast Metabolism',
                'reader',
                'author'
            ],
            array_keys($storage->getUserAssignments('reader A'))
        );
    }

    public function testAssignmentExist(): void
    {
        $storage = $this->createStorage();

        $this->assertTrue($storage->assignmentExist('deletePost'));
        $this->assertFalse($storage->assignmentExist('nonExistAssignment'));
    }

    public function testRemoveAssignment(): void
    {
        $storage = $this->createStorage();
        $storage->removeAssignment('author B', $storage->getItemByName('deletePost'));
        $this->assertEquals(['author'], array_keys($storage->getUserAssignments('author B')));
    }

    public function testRemoveAllAssignments(): void
    {
        $storage = $this->createStorage();
        $storage->removeAllAssignments('author B');
        $this->assertEmpty($storage->getUserAssignments('author B'));
    }

    public function testRemoveItem(): void
    {
        $storage = $this->createStorage();
        $storage->removeItem($storage->getItemByName('reader'));
        $this->assertEquals(
            [
                'Fast Metabolism',
                'createPost',
                'readPost',
                'deletePost',
                'updatePost',
                'updateAnyPost',
                'withoutChildren',
                'author',
                'admin',
            ],
            array_keys($storage->getItems())
        );

        $this->assertEquals(
            [
                'withoutChildren',
                'author',
                'admin',
            ],
            array_keys($storage->getRoles())
        );

        $this->assertNull($storage->getUserAssignmentByName('reader A', 'reader'));
    }

    public function testUpdateItem(): void
    {
        $storage = $this->createStorage();
        $storage->updateItem('reader', $storage->getItemByName('reader')->withName('new reader'));
        $this->assertEquals(
            [
                'withoutChildren',
                'author',
                'admin',
                'new reader',
            ],
            array_keys($storage->getRoles())
        );
        $this->assertNull($storage->getRoleByName('reader'));
    }


    public function testRemoveRule(): void
    {
        $storage = $this->createStorage();
        $storage->removeRule('isAuthor');
        $this->assertEmpty($storage->getRules());
    }

    public function testAddRule(): void
    {
        $storage = $this->createStorage();
        $storage->addRule(new EasyRule());
        $this->assertEquals(
            [
                'isAuthor',
                EasyRule::class
            ],
            array_keys($storage->getRules())
        );
    }

    protected function tearDown(): void
    {
        $this->clearStudFiles();
        parent::tearDown();
    }

    protected function setUp(): void
    {
        $this->setDataPath();
        $this->addStudFiles();
        parent::setUp();
    }

    private function createStorage(): PhpStorage
    {
        return new PhpStorage($this->testDataPath);
    }

    private function setDataPath(): void
    {
        $this->testDataPath = $this->createDataPath();
    }

    private function createDataPath(): string
    {
        return sys_get_temp_dir() . '/' . str_replace('\\', '_', get_class($this)) . uniqid('', false);
    }

    private function getStubDirectory(): string
    {
        return __DIR__ . static::STUB_DIRECTORY;
    }

    private function addStudFiles(): void
    {
        FileHelper::copyDirectory($this->getStubDirectory(), $this->testDataPath);
    }

    private function clearStudFiles(): void
    {
        FileHelper::removeDirectory($this->testDataPath);
    }
}
