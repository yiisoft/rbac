<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use PHPUnit\Framework\TestCase;
use Yiisoft\Files\FileHelper;
use InvalidArgumentException;
use RuntimeException;
use Yiisoft\Rbac\Manager;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\PhpStorage;
use Yiisoft\Rbac\Role;
use Yiisoft\Rbac\RuleFactory\ClassNameRuleFactory;
use Yiisoft\Rbac\Storage;

/**
 * @group rbac
 */
final class ManagerTest extends TestCase
{
    private const STUB_DIRECTORY = '/Stub/';
    private string $testDataPath;

    public function testRevokeAllClearAllUseAssignments(): void
    {
        $storage = $this->createStorage();
        $manager = $this->createManager($storage);
        $manager->revokeAll('author B');
        $this->assertEmpty($storage->getUserAssignments('author B'));
    }

    public function testReturnTrueWhenChildExists(): void
    {
        $storage = $this->createStorage();
        $manager = $this->createManager($storage);

        $reader = $storage->getRoleByName('reader');
        $readPost = $storage->getPermissionByName('readPost');
        $this->assertTrue($manager->hasChild($reader, $readPost));
    }

    public function testReturnFalseWhenHasNoChild(): void
    {
        $storage = $this->createStorage();
        $manager = $this->createManager($storage);

        $reader = $storage->getRoleByName('reader');
        $updatePost = $storage->getPermissionByName('updatePost');
        $this->assertFalse($manager->hasChild($reader, $updatePost));
    }

    public function testRemoveChildren(): void
    {
        $storage = $this->createStorage();
        $manager = $this->createManager($storage);

        $author = $storage->getRoleByName('author');
        $createPost = $storage->getPermissionByName('createPost');
        $updatePost = $storage->getPermissionByName('updatePost');

        $manager->removeChildren($author);

        $this->assertFalse($manager->hasChild($author, $createPost));
        $this->assertFalse($manager->hasChild($author, $updatePost));
    }

    public function testRemoveChild(): void
    {
        $storage = $this->createStorage();
        $manager = $this->createManager($storage);

        $author = $storage->getRoleByName('author');
        $createPost = $storage->getPermissionByName('createPost');
        $updatePost = $storage->getPermissionByName('updatePost');

        $manager->removeChild($author, $createPost);

        $this->assertFalse($manager->hasChild($author, $createPost));
        $this->assertTrue($manager->hasChild($author, $updatePost));
    }

    public function testRuleSetWhenUpdatingItem(): void
    {
        $storage = $this->createStorage();
        $manager = $this->createManager($storage);

        $newRule = new EasyRule();

        $permissionName = 'newPermission';
        $permission = (new Permission($permissionName))
            ->withRuleName($newRule->getName());

        $manager->updatePermission($permissionName, $permission);
        $this->assertNotNull($storage->getPermissionByName($permissionName));
        $this->assertNotNull($storage->getRuleByName($newRule->getName()));
    }

    public function testDefaultRolesSetWithClosure(): void
    {
        $manager = $this->createManager($this->createStorage());
        $manager->setDefaultRoles(
            static function () {
                return ['newDefaultRole'];
            }
        );

        $this->assertEquals(['newDefaultRole'], $manager->getDefaultRoles());
    }

    public function testReturnFalseForNonExistingUserAndNoDefaultRoles(): void
    {
        $manager = $this->createManager($this->createStorage());
        $manager->setDefaultRoles([]);
        $this->assertFalse($manager->userHasPermission('unknown user', 'createPost'));
    }

    public function testRuleSetWhenAddingItem(): void
    {
        $storage = $this->createStorage();
        $manager = $this->createManager($storage);

        $newRule = new EasyRule();
        $itemName = 'newPermission';
        $item = (new Permission($itemName))
            ->withRuleName($newRule->getName());

        $manager->addPermission($item);
        $this->assertNotNull($storage->getPermissionByName($itemName));
        $this->assertNotNull($storage->getRuleByName($newRule->getName()));
    }

    public function testAddRole(): void
    {
        $storage = $this->createStorage();
        $manager = $this->createManager($storage);
        $role = (new Role('admin'))
            ->withDescription('administrator');

        $manager->addRole($role);
        $this->assertNotNull($storage->getRoleByName('admin'));
    }

    public function testAddPermission(): void
    {
        $storage = $this->createStorage();
        $manager = $this->createManager($storage);
        $permission = (new Permission('edit post'))
            ->withDescription('edit a post');

        $manager->addPermission($permission);
        $this->assertNotNull($storage->getPermissionByName('edit post'));
    }

    public function testAddRule(): void
    {
        $storage = $this->createStorage();
        $manager = $this->createManager($storage);

        $ruleName = 'isReallyReallyAuthor';
        $rule = new AuthorRule($ruleName, true);
        $manager->addRule($rule);

        /** @var AuthorRule $rule */
        $rule = $storage->getRuleByName($ruleName);
        $this->assertEquals($ruleName, $rule->getName());
        $this->assertTrue($rule->isReallyReally());
    }

    public function testGetChildren(): void
    {
        $storage = $this->createStorage();
        $manager = $this->createManager($storage);

        $user = new Role('user');
        $manager->addRole($user);
        $this->assertCount(0, $storage->getChildrenByName($user->getName()));

        $changeName = new Permission('changeName');
        $manager->addPermission($changeName);
        $manager->addChild($user, $changeName);
        $this->assertCount(1, $storage->getChildrenByName($user->getName()));
    }

    public function testUserHasPermission(): void
    {
        $manager = $this->createManager($this->createStorage());

        $testSuites = [
            'reader A' => [
                'createPost' => false,
                'readPost' => true,
                'updatePost' => false,
                'updateAnyPost' => false,
                'reader' => false,
            ],
            'author B' => [
                'createPost' => true,
                'readPost' => true,
                'updatePost' => true,
                'deletePost' => true,
                'updateAnyPost' => false,
            ],
            'admin C' => [
                'createPost' => true,
                'readPost' => true,
                'updatePost' => false,
                'updateAnyPost' => true,
                'nonExistingPermission' => false,
                null => false,
            ],
            'guest' => [
                'createPost' => false,
                'readPost' => false,
                'updatePost' => false,
                'deletePost' => false,
                'updateAnyPost' => false,
                'blablabla' => false,
                null => false,
            ],
        ];

        $params = ['authorID' => 'author B'];

        foreach ($testSuites as $user => $tests) {
            foreach ($tests as $permission => $result) {
                $this->assertEquals(
                    $result,
                    $manager->userHasPermission($user, $permission, $params),
                    "Checking \"$user\" can \"$permission\""
                );
            }
        }
    }

    public function testGetPermissionsByRole(): void
    {
        $permissions = $this->createManager($this->createStorage())->getPermissionsByRole('admin');
        $expectedPermissions = ['createPost', 'updatePost', 'readPost', 'updateAnyPost'];
        $this->assertCount(count($expectedPermissions), $permissions);
        foreach ($expectedPermissions as $permissionName) {
            $this->assertInstanceOf(Permission::class, $permissions[$permissionName]);
        }
    }

    public function testGetPermissionsByUser(): void
    {
        $permissions = $this->createManager($this->createStorage())->getPermissionsByUser('author B');
        $expectedPermissions = ['deletePost', 'createPost', 'updatePost', 'readPost'];
        $this->assertCount(count($expectedPermissions), $permissions);
        foreach ($expectedPermissions as $permissionName) {
            $this->assertInstanceOf(Permission::class, $permissions[$permissionName]);
        }
    }

    public function testGetRolesByUser(): void
    {
        $storage = $this->createStorage();
        $manager = $this->createManager($storage);

        $reader = $storage->getRoleByName('reader');
        $manager->assign($reader, '0');
        $manager->assign($reader, '123');

        $roles = $manager->getRolesByUser('reader A');
        $this->assertEquals(['myDefaultRole', 'reader'], array_keys($roles));

        $roles = $manager->getRolesByUser('0');
        $this->assertEquals(['myDefaultRole', 'reader'], array_keys($roles));

        $roles = $manager->getRolesByUser('123');
        $this->assertEquals(['myDefaultRole', 'reader'], array_keys($roles));
    }

    public function testGetChildRoles(): void
    {
        $manager = $this->createManager($this->createStorage());

        $roles = $manager->getChildRoles('withoutChildren');
        $this->assertCount(1, $roles);
        $this->assertInstanceOf(Role::class, reset($roles));
        $this->assertSame(reset($roles)->getName(), 'withoutChildren');

        $roles = $manager->getChildRoles('reader');
        $this->assertCount(1, $roles);
        $this->assertInstanceOf(Role::class, reset($roles));
        $this->assertSame(reset($roles)->getName(), 'reader');

        $roles = $manager->getChildRoles('author');
        $this->assertCount(2, $roles);
        $this->assertArrayHasKey('author', $roles);
        $this->assertArrayHasKey('reader', $roles);

        $roles = $manager->getChildRoles('admin');
        $this->assertCount(3, $roles);
        $this->assertArrayHasKey('admin', $roles);
        $this->assertArrayHasKey('author', $roles);
        $this->assertArrayHasKey('reader', $roles);
    }

    public function testAssignMultipleRoles(): void
    {
        $storage = $this->createStorage();
        $manager = $this->createManager($storage);

        $reader = $storage->getRoleByName('reader');
        $author = $storage->getRoleByName('author');
        $manager->assign($reader, 'readingAuthor');
        $manager->assign($author, 'readingAuthor');

        $this->assertEquals(
            [
                'myDefaultRole',
                'reader',
                'author'
            ],
            array_keys($manager->getRolesByUser('readingAuthor'))
        );
    }

    public function testUserIdsByRole(): void
    {
        $manager = $this->createManager($this->createStorage());
        $this->assertEquals(
            [
                'reader A',
                'author B',
                'admin C'
            ],
            $manager->getUserIdsByRole('reader')
        );
        $this->assertEquals(
            [
                'author B',
                'admin C'
            ],
            $manager->getUserIdsByRole('author')
        );
        $this->assertEquals(['admin C'], $manager->getUserIdsByRole('admin'));
    }

    public function testGetAssignmentsByRoleNonExistentRole(): void
    {
        $manager = $this->createManager($this->createStorage());
        $this->assertEmpty($manager->getUserIdsByRole('nonExistRole'));
    }

    public function testCanAddChild(): void
    {
        $manager = $this->createManager($this->createStorage());

        $author = new Role('author');
        $reader = new Role('reader');

        $this->assertTrue($manager->canAddChild($author, $reader));
        $this->assertFalse($manager->canAddChild($reader, $author));
    }

    public function testCanNotAddRoleToPermission(): void
    {
        $manager = $this->createManager($this->createStorage());
        $permission = new Permission('test_permission');
        $role = new Role('test_role');
        $this->assertFalse($manager->canAddChild($permission, $role));
        $this->assertTrue($manager->canAddChild($role, $permission));
    }

    public function testAssignUnknownItem(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unknown role "nonExistRole".');
        $manager = $this->createManager($this->createStorage());
        $role = new Role('nonExistRole');
        $manager->assign($role, 'reader');
    }

    public function testAssignAlreadyAssignedItem(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('"reader" role has already been assigned to user reader A.');

        $storage = $this->createStorage();
        $manager = $this->createManager($storage);
        $role = $storage->getRoleByName('reader');
        $manager->assign($role, 'reader A');
    }

    public function testAssignRuleToRoleByName(): void
    {
        $storage = $this->createStorage();
        $storage->clear();
        $manager = $this->createManager($storage);
        $userId = '3';
        $storage->clear();

        $rule = new ActionRule();
        $manager->addRule($rule);

        $role = (new Role('Reader'))
            ->withRuleName($rule->getName());
        $manager->addRole($role);

        $permission = new Permission('manage');
        $manager->addPermission($permission);
        $manager->addChild($role, $permission);

        $manager->assign($role, $userId);

        $this->assertTrue($manager->userHasPermission($userId, 'manage', ['action' => 'read']));
        $this->assertFalse($manager->userHasPermission($userId, 'manage', ['action' => 'write']));
    }

    public function testAssignRuleToPermissionByName(): void
    {
        $storage = $this->createStorage();
        $storage->clear();
        $manager = $this->createManager($storage);
        $userId = '3';
        $rule = new ActionRule();
        $manager->addRule($rule);
        $item = (new Permission('manage'))
            ->withRuleName($rule->getName());
        $manager->addPermission($item);
        $manager->assign($item, $userId);

        $this->assertTrue($manager->userHasPermission($userId, 'manage', ['action' => 'read']));
        $this->assertFalse($manager->userHasPermission($userId, 'manage', ['action' => 'write']));
    }

    public function testUpdateRoleNameAndRule(): void
    {
        $storage = $this->createStorage();
        $storage->clear();
        $manager = $this->createManager($storage);
        $userId = '3';

        $manager->addRule(new ActionRule());
        $manager->addRule(new AuthorRule());

        $role = (new Role('Reader'))
            ->withRuleName('action_rule');
        $manager->addRole($role);
        $manager->assign($role, $userId);

        $permission = new Permission('manage');
        $manager->addPermission($permission);
        $manager->addChild($role, $permission);

        $role = $storage->getRoleByName('Reader')
            ->withName('AdminPost')
            ->withRuleName('isAuthor');
        $manager->updateRole('Reader', $role);

        $this->assertArrayNotHasKey(
            'Reader',
            $manager->getRolesByUser($userId),
            'Old role should not be assigned'
        );

        $this->assertArrayHasKey(
            'AdminPost',
            $manager->getRolesByUser($userId),
            'New role should be assigned'
        );

        $role = $storage->getRoleByName('AdminPost');
        $this->assertSame('isAuthor', $role->getRuleName(), 'Rule should have new name');
    }

    public function testUpdatePermissionNameAndRule(): void
    {
        $storage = $this->createStorage();
        $storage->clear();
        $manager = $this->createManager($storage);
        $userId = '3';

        $manager->addRule(new ActionRule());
        $manager->addRule(new AuthorRule());

        $manage = (new Permission('manage'))
            ->withRuleName('action_rule');
        $manager->addPermission($manage);
        $manager->assign($manage, $userId);

        $manage = $storage->getPermissionByName('manage')
            ->withName('admin')
            ->withRuleName('isAuthor');
        $manager->updatePermission('manage', $manage);

        $this->assertTrue($manager->userHasPermission($userId, 'admin', ['authorID' => 3]));
        $this->assertFalse($manager->userHasPermission($userId, 'manage', ['authorID' => 3]));
    }

    public function testRevokeRole(): void
    {
        $userId = '3';
        $storage = $this->createStorage();
        $storage->clear();
        $manager = $this->createManager($storage);

        $role = new Role('Admin');
        $manager->addRole($role);
        $manager->assign($role, $userId);
        $manager->revoke($role, $userId);

        $this->assertNotContains('Admin', $manager->getRolesByUser($userId));
    }

    public function testRevokePermission(): void
    {
        $storage = $this->createStorage();
        $storage->clear();
        $manager = $this->createManager($storage);
        $userId = '3';


        $permission = new Permission('manage');
        $manager->addPermission($permission);
        $manager->assign($permission, $userId);
        $manager->revoke($permission, $userId);

        $this->assertFalse($manager->userHasPermission($userId, 'manage'));
    }

    public function testRevokePermissionWithRule(): void
    {
        $storage = $this->createStorage();
        $storage->clear();
        $manager = $this->createManager($storage);
        $userId = '3';

        $rule = new ActionRule();
        $manager->addRule($rule);

        $permission = (new Permission('manage'))
            ->withRuleName($rule->getName());
        $manager->addPermission($permission);
        $manager->assign($permission, $userId);

        $manager->revoke($permission, $userId);

        $this->assertFalse($manager->userHasPermission($userId, 'manage', ['action' => 'read']));
        $this->assertFalse($manager->userHasPermission($userId, 'manage', ['action' => 'write']));
    }

    public function testRevokeRoleWithRule(): void
    {
        $storage = $this->createStorage();
        $storage->clear();
        $manager = $this->createManager($storage);

        $userId = '3';

        $rule = new ActionRule();
        $manager->addRule($rule);

        $role = (new Role('Admin'))
            ->withRuleName($rule->getName());
        $manager->addRole($role);
        $manager->assign($role, $userId);

        $manager->revoke($role, $userId);

        $this->assertFalse($manager->userHasPermission($userId, 'Admin', ['action' => 'read']));
        $this->assertFalse($manager->userHasPermission($userId, 'Admin', ['action' => 'write']));
    }

    /**
     * @see https://github.com/yiisoft/yii2/issues/10176
     * @see https://github.com/yiisoft/yii2/issues/12681
     */
    public function testRuleWithPrivateFields(): void
    {
        $storage = $this->createStorage();
        $storage->clear();
        $manager = $this->createManager($storage);

        $rule = new ActionRule();
        $manager->addRule($rule);
        $this->assertInstanceOf(ActionRule::class, $storage->getRuleByName('action_rule'));
    }

    public function testDefaultRolesWithClosureReturningNonArrayValue(): void
    {
        $manager = $this->createManager($this->createStorage());
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Default roles closure must return an array');
        $manager->setDefaultRoles(
            static function () {
                return 'test';
            }
        );
    }

    public function testDefaultRolesWithNonArrayValue(): void
    {
        $manager = $this->createManager($this->createStorage());
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Default roles must be either an array or a callable');
        $manager->setDefaultRoles('test');
    }

    public function testUpdateRule(): void
    {
        $storage = $this->createStorage();
        $manager = $this->createManager($storage);

        $rule = $storage->getRuleByName('isAuthor');
        $rule = $rule
            ->withName('newName')
            ->withReallyReally(false);

        $manager->updateRule('isAuthor', $rule);

        $rule = $storage->getRuleByName('isAuthor');
        $this->assertNull($rule);

        /** @var AuthorRule $rule */
        $rule = $storage->getRuleByName('newName');
        $this->assertEquals('newName', $rule->getName());
        $this->assertFalse($rule->isReallyReally());

        $rule = $rule->withReallyReally(true);
        $manager->updateRule('newName', $rule);

        /** @var AuthorRule $rule */
        $rule = $storage->getRuleByName('newName');
        $this->assertTrue($rule->isReallyReally());

        $item = $storage->getPermissionByName('createPost')
            ->withName('new createPost');
        $manager->updatePermission('createPost', $item);

        $item = $storage->getPermissionByName('createPost');
        $this->assertNull($item);

        $item = $storage->getPermissionByName('new createPost');
        $this->assertEquals('new createPost', $item->getName());
    }

    public function testUpdateItemName(): void
    {
        $storage = $this->createStorage();
        $manager = $this->createManager($storage);


        $name = 'readPost';
        $permission = $storage->getPermissionByName($name);
        $permission = $permission->withName('UPDATED-NAME');
        $manager->updatePermission($name, $permission);

        $this->assertNull($storage->getPermissionByName('readPost'));
        $this->assertNotNull($storage->getPermissionByName('UPDATED-NAME'));
    }

    public function testUpdateDescription(): void
    {
        $storage = $this->createStorage();
        $manager = $this->createManager($storage);

        $name = 'readPost';
        $permission = $storage->getPermissionByName($name);
        $newDescription = 'UPDATED-DESCRIPTION';
        $permission = $permission->withDescription($newDescription);
        $manager->updatePermission($name, $permission);

        $permission = $storage->getPermissionByName('readPost');
        $this->assertEquals($newDescription, $permission->getDescription());
    }

    public function testOverwriteName(): void
    {
        $storage = $this->createStorage();
        $manager = $this->createManager($storage);
        $name = 'readPost';
        $permission = $storage->getPermissionByName($name);
        $permission = $permission->withName('createPost');
        $this->expectException(InvalidArgumentException::class);
        $manager->updatePermission($name, $permission);
    }

    public function testAddChild(): void
    {
        $storage = $this->createStorage();
        $manager = $this->createManager($storage);

        $role = $storage->getRoleByName('reader');
        $permission = $storage->getPermissionByName('createPost');

        $manager->addChild($role, $permission);
        $this->assertEquals(
            [
                'readPost',
                'createPost'
            ],
            array_keys($storage->getChildrenByName('reader'))
        );
    }

    public function testAddChildNotHasItem(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Either "new reader" or "createPost" does not exist.');

        $storage = $this->createStorage();
        $manager = $this->createManager($storage);

        $manager->addChild(
            new Role('new reader'),
            $storage->getPermissionByName('createPost')
        );
    }

    public function testAddChildEqualName(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot add "createPost" as a child of itself.');

        $storage = $this->createStorage();
        $manager = $this->createManager($storage);

        $manager->addChild(
            new Role('createPost'),
            $storage->getPermissionByName('createPost')
        );
    }

    public function testAddChildCanBeParentOfItem(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Can not add "reader" role as a child of "createPost" permission.');

        $storage = $this->createStorage();
        $manager = $this->createManager($storage);

        $manager->addChild(
            $storage->getPermissionByName('createPost'),
            $storage->getRoleByName('reader')
        );
    }

    public function testAddChildAlreadyAdded(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The item "reader" already has a child "readPost".');

        $storage = $this->createStorage();
        $manager = $this->createManager($storage);

        $manager->addChild(
            $storage->getRoleByName('reader'),
            $storage->getPermissionByName('readPost')
        );
    }

    private function createManager(Storage $storage): Manager
    {
        return (new Manager($storage, new ClassNameRuleFactory()))
            ->setDefaultRoles(['myDefaultRole']);
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
