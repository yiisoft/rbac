<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

/**
 * Mock for the time() function for RBAC classes. Avoid random test fails.
 *
 * @return int
 */
function time()
{
    return PhpManagerTest::$time ?: \time();
}

use PHPUnit\Framework\TestCase;
use Yiisoft\Files\FileHelper;
use Yiisoft\Rbac\Assignment;
use Yiisoft\Rbac\Exceptions\InvalidArgumentException;
use Yiisoft\Rbac\Exceptions\InvalidValueException;
use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\ItemInterface;
use Yiisoft\Rbac\Manager\PhpManager;
use Yiisoft\Rbac\ManagerInterface;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\Role;
use Yiisoft\Rbac\Rule;
use Yiisoft\Rbac\RuleFactory\ClassNameRuleFactory;
use Yiisoft\Rbac\Storage;

/**
 * @group rbac
 */
final class PhpManagerTest extends TestCase
{
    public static ?int $time;
    public static ?int $filemtime;
    private string $testDataPath;
    private ?Storage $storage = null;
    private ?PhpManager $auth = null;

    public function testSaveLoad(): void
    {
        static::$time = static::$filemtime = \time();
        $this->prepareData();
        $items = $this->storage->items;
        $children = $this->storage->children;
        $assignments = $this->storage->assignments;
        $rules = $this->storage->rules;

        $this->createManager();

        $this->assertEquals($items, $this->storage->getItems());
        $this->assertNotEmpty($this->storage->getItems());

        $this->assertEquals($children, $this->storage->getChildren());
        $this->assertNotEmpty($this->storage->getChildren());

        $this->assertEquals($assignments, $this->storage->getAssignments());
        $this->assertNotEmpty($this->storage->getAssignments());

        $this->assertEquals($rules, $this->storage->getRules());
        $this->assertNotEmpty($this->storage->getRules());
    }

    public function testSaveAssignments(): void
    {
        $this->auth->removeAll();

        $role = new Role('Admin');
        $this->auth->add($role);
        $this->auth->assign($role, '13');

        $this->assertStringContainsString(
            'Admin',
            file_get_contents($this->getAssignmentFilePath()),
            'Role "Admin" was not added when saving'
        );

        $role = $role->withName('NewAdmin');
        $this->auth->update('Admin', $role);
        $this->assertStringContainsString(
            'NewAdmin',
            file_get_contents($this->getAssignmentFilePath()),
            'Role "NewAdmin" was not added when saving'
        );
        $this->auth->remove($role);
        $this->assertStringNotContainsString(
            'Admin',
            file_get_contents($this->getAssignmentFilePath()),
            'Role "Admin" was not removed when saving'
        );

        $this->auth->remove($role);
        $this->assertStringNotContainsString(
            'NewAdmin',
            file_get_contents($this->getAssignmentFilePath()),
            'Role "NewAdmin" was not removed when saving'
        );
    }

    public function testReturnExceptionWhenAddingUnknownItemType(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Adding unsupported item type.');
        $this->auth->add($this->getCustomItem());
    }

    public function testRevokeAllClearAllUseAssignments(): void
    {
        $this->prepareData();
        $this->auth->revokeAll('author B');
        $this->assertEmpty($this->auth->getAssignments('author B'));
    }

    public function testReturnUserAssignment(): void
    {
        $this->prepareData();
        $this->assertInstanceOf(Assignment::class, $this->auth->getAssignment('author', 'author B'));
    }

    public function testReturnNullForUserWithoutAssignment(): void
    {
        $this->prepareData();
        $this->assertNull($this->auth->getAssignment('author', 'guest'));
    }

    public function testReturnEmptyArrayWithNoAssignments(): void
    {
        $this->prepareData();
        $this->auth->removeAllAssignments();
        $this->assertEmpty($this->auth->getAssignments('author B'));
        $this->assertEmpty($this->auth->getAssignments('author A'));
    }

    public function testReturnTrueWhenChildExists(): void
    {
        $this->prepareData();

        $reader = $this->auth->getRole('reader');
        $readPost = $this->auth->getPermission('readPost');

        $this->assertTrue($this->auth->hasChild($reader, $readPost));
    }

    public function testReturnFalseWhenHasNoChild(): void
    {
        $this->prepareData();

        $reader = $this->auth->getRole('reader');
        $updatePost = $this->auth->getPermission('updatePost');

        $this->assertFalse($this->auth->hasChild($reader, $updatePost));
    }

    public function testRemoveChildren(): void
    {
        $this->prepareData();

        $author = $this->auth->getRole('author');
        $createPost = $this->auth->getPermission('createPost');
        $updatePost = $this->auth->getPermission('updatePost');

        $this->auth->removeChildren($author);

        $this->assertFalse($this->auth->hasChild($author, $createPost));
        $this->assertFalse($this->auth->hasChild($author, $updatePost));
    }

    public function testRemoveChild(): void
    {
        $this->prepareData();

        $author = $this->auth->getRole('author');
        $createPost = $this->auth->getPermission('createPost');
        $updatePost = $this->auth->getPermission('updatePost');

        $this->auth->removeChild($author, $createPost);

        $this->assertFalse($this->auth->hasChild($author, $createPost));
        $this->assertTrue($this->auth->hasChild($author, $updatePost));
    }

    public function testRuleSetWhenUpdatingItem(): void
    {
        $newRule = new EasyRule();

        $permissionName = 'newPermission';
        $permission = (new Permission($permissionName))
            ->withRuleName($newRule->getName());

        $this->auth->update($permissionName, $permission);
        $this->assertNotNull($this->auth->getPermission($permissionName));
        $this->assertNotNull($this->auth->getRule($newRule->getName()));
    }

    public function testReturnExceptionWhenUpdateWithUnknownItemType(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Updating unsupported item type.');
        $customItem = $this->getCustomItem();
        $this->auth->update($customItem->getName(), $customItem);
    }

    public function testDefaultRolesSetWithClosure(): void
    {
        $this->auth->setDefaultRoles(
            static function () {
                return ['newDefaultRole'];
            }
        );

        $this->assertEquals($this->auth->getDefaultRoles(), ['newDefaultRole']);
    }

    public function testReturnFalseForNonExistingUserAndNoDefaultRoles(): void
    {
        $this->auth->setDefaultRoles([]);
        $this->assertFalse($this->auth->userHasPermission('unknown user', 'createPost'));
    }

    public function testReturnExceptionWhenRemoveByUnknownItemType(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Removing unsupported item type.');
        $this->auth->remove($this->getCustomItem());
    }

    public function testRuleSetWhenAddingItem(): void
    {
        $newRule = new EasyRule();
        $itemName = 'newPermission';
        $item = (new Permission($itemName))
            ->withRuleName($newRule->getName());

        $this->auth->add($item);
        $this->assertNotNull($this->auth->getPermission($itemName));
        $this->assertNotNull($this->auth->getRule($newRule->getName()));
    }

    public function testGetRuleReturnNullForNonExistingRole(): void
    {
        $this->prepareData();
        $author = $this->auth->getRole('createPost');

        $this->assertNull($author);
    }

    public function testAddRole(): void
    {
        $role = (new Role('admin'))
            ->withDescription('administrator');

        $this->auth->add($role);
        $this->assertNotNull($this->auth->getRole('admin'));
    }

    public function testAddPermission(): void
    {
        $permission = (new Permission('edit post'))
            ->withDescription('edit a post');

        $this->auth->add($permission);
        $this->assertNotNull($this->auth->getPermission('edit post'));
    }

    public function testAddRule(): void
    {
        $this->prepareData();

        $ruleName = 'isReallyReallyAuthor';
        $rule = new AuthorRule($ruleName, true);
        $this->auth->add($rule);

        /** @var AuthorRule $rule */
        $rule = $this->auth->getRule($ruleName);
        $this->assertEquals($ruleName, $rule->getName());
        $this->assertTrue($rule->isReallyReally());
    }

    public function testGetChildren(): void
    {
        $user = new Role('user');
        $this->auth->add($user);
        $this->assertCount(0, $this->auth->getChildren($user->getName()));

        $changeName = new Permission('changeName');
        $this->auth->add($changeName);
        $this->auth->addChild($user, $changeName);
        $this->assertCount(1, $this->auth->getChildren($user->getName()));
    }

    public function testGetRule(): void
    {
        $this->prepareData();

        $rule = $this->auth->getRule('isAuthor');
        $this->assertInstanceOf(Rule::class, $rule);
        $this->assertEquals('isAuthor', $rule->getName());
        $this->assertEquals(
            ['name' => 'isAuthor'],
            $rule->getAttributes()
        );

        $rule = $this->auth->getRule('nonExisting');
        $this->assertNull($rule);
    }

    public function testGetRules(): void
    {
        $this->prepareData();

        $rule = new AuthorRule('isReallyReallyAuthor', true);
        $this->auth->add($rule);

        $rules = $this->auth->getRules();

        $ruleNames = [];
        foreach ($rules as $rule) {
            $ruleNames[] = $rule->getName();
        }

        $this->assertContains('isReallyReallyAuthor', $ruleNames);
        $this->assertContains('isAuthor', $ruleNames);
    }

    public function testRemoveRule(): void
    {
        $this->prepareData();

        $this->auth->remove($this->auth->getRule('isAuthor'));
        $rules = $this->auth->getRules();

        $this->assertEmpty($rules);

        $this->auth->remove($this->auth->getPermission('createPost'));
        $item = $this->auth->getPermission('createPost');
        $this->assertNull($item);
    }

    public function testUserHasPermission(): void
    {
        $this->prepareData();

        $testSuites = [
            'reader A' => [
                'createPost' => false,
                'readPost' => true,
                'updatePost' => false,
                'updateAnyPost' => false,
                // roles checked directly should return false:
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
                // all actions denied for guest (user not exists)
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
                    $this->auth->userHasPermission($user, $permission, $params),
                    "Checking \"$user\" can \"$permission\""
                );
            }
        }
    }

    public function testGetPermissionsByRole(): void
    {
        $this->prepareData();
        $permissions = $this->auth->getPermissionsByRole('admin');
        $expectedPermissions = ['createPost', 'updatePost', 'readPost', 'updateAnyPost'];
        $this->assertCount(count($expectedPermissions), $permissions);
        foreach ($expectedPermissions as $permissionName) {
            $this->assertInstanceOf(Permission::class, $permissions[$permissionName]);
        }
    }

    public function testGetPermissionsByUser(): void
    {
        $this->prepareData();
        $permissions = $this->auth->getPermissionsByUser('author B');
        $expectedPermissions = ['deletePost', 'createPost', 'updatePost', 'readPost'];
        $this->assertCount(count($expectedPermissions), $permissions);
        foreach ($expectedPermissions as $permissionName) {
            $this->assertInstanceOf(Permission::class, $permissions[$permissionName]);
        }
    }

    public function testGetRole(): void
    {
        $this->prepareData();
        $author = $this->auth->getRole('author');
        $this->assertEquals(Item::TYPE_ROLE, $author->getType());
        $this->assertEquals('author', $author->getName());
        $this->assertEquals(
            [
                'name' => 'author',
                'description' => '',
                'ruleName' => null,
                'type' => 'role',
                'updatedAt' => time(),
                'createdAt' => time(),
            ],
            $author->getAttributes()
        );
    }

    public function testGetPermission(): void
    {
        $this->prepareData();
        $createPost = $this->auth->getPermission('createPost');
        $this->assertEquals(Item::TYPE_PERMISSION, $createPost->getType());
        $this->assertEquals('createPost', $createPost->getName());
        $this->assertEquals(
            [
                'name' => 'createPost',
                'description' => 'create a post',
                'ruleName' => null,
                'type' => 'permission',
                'updatedAt' => time(),
                'createdAt' => time(),
            ],
            $createPost->getAttributes()
        );
    }

    public function testGetRolesByUser(): void
    {
        $this->prepareData();
        $reader = $this->auth->getRole('reader');
        $this->auth->assign($reader, '0');
        $this->auth->assign($reader, '123');

        $roles = $this->auth->getRolesByUser('reader A');
        $this->assertInstanceOf(Role::class, reset($roles));
        $this->assertEquals($roles['reader']->getName(), 'reader');

        $roles = $this->auth->getRolesByUser('0');
        $this->assertInstanceOf(Role::class, reset($roles));
        $this->assertEquals($roles['reader']->getName(), 'reader');

        $roles = $this->auth->getRolesByUser('123');
        $this->assertInstanceOf(Role::class, reset($roles));
        $this->assertEquals($roles['reader']->getName(), 'reader');

        $this->assertContains('myDefaultRole', array_keys($roles));
    }

    public function testGetChildRoles(): void
    {
        $this->prepareData();

        $roles = $this->auth->getChildRoles('withoutChildren');
        $this->assertCount(1, $roles);
        $this->assertInstanceOf(Role::class, reset($roles));
        $this->assertSame(reset($roles)->getName(), 'withoutChildren');

        $roles = $this->auth->getChildRoles('reader');
        $this->assertCount(1, $roles);
        $this->assertInstanceOf(Role::class, reset($roles));
        $this->assertSame(reset($roles)->getName(), 'reader');

        $roles = $this->auth->getChildRoles('author');
        $this->assertCount(2, $roles);
        $this->assertArrayHasKey('author', $roles);
        $this->assertArrayHasKey('reader', $roles);

        $roles = $this->auth->getChildRoles('admin');
        $this->assertCount(3, $roles);
        $this->assertArrayHasKey('admin', $roles);
        $this->assertArrayHasKey('author', $roles);
        $this->assertArrayHasKey('reader', $roles);
    }

    public function testAssignMultipleRoles(): void
    {
        $this->prepareData();

        $reader = $this->auth->getRole('reader');
        $author = $this->auth->getRole('author');
        $this->auth->assign($reader, 'readingAuthor');
        $this->auth->assign($author, 'readingAuthor');

        $this->createManager();

        $roles = $this->auth->getRolesByUser('readingAuthor');
        $roleNames = [];
        foreach ($roles as $role) {
            $roleNames[] = $role->getName();
        }

        $this->assertContains(
            'reader',
            $roleNames,
            'Roles should contain reader. Currently it has: ' . implode(', ', $roleNames)
        );
        $this->assertContains(
            'author',
            $roleNames,
            'Roles should contain author. Currently it has: ' . implode(', ', $roleNames)
        );
    }

    public function testHasAssignments(): void
    {
        $this->auth->removeAll();

        $this->assertFalse(
            $this->auth->hasAssignments('non_existing'),
            'Non existing permission should not have assignments'
        );

        $admin = new Role('admin');
        $this->auth->add($admin);
        $this->auth->assign($admin, '1');

        $this->assertTrue(
            $this->auth->hasAssignments('admin'),
            'Existing assigned role should have assignments'
        );

        $role = new Role('unassigned');
        $this->auth->add($role);
        $this->assertFalse(
            $this->auth->hasAssignments('unassigned'),
            'Existing not assigned role should not have assignments'
        );
    }

    public function testGetAssignmentsByRole(): void
    {
        $this->prepareData();
        $this->createManager();

        $this->assertEqualsCanonicalizing(
            [
                'reader A',
                'author B',
                'admin C'
            ],
            $this->auth->getUserIdsByRole('reader'),
            ''
        );

        $this->assertEquals(
            [
                'author B',
                'admin C'
            ],
            $this->auth->getUserIdsByRole('author')
        );

        $this->assertEquals(['admin C'], $this->auth->getUserIdsByRole('admin'));
    }

    public function testGetAssignmentsByRoleNonExistentRole(): void
    {
        $this->prepareData();
        $this->createManager();
        $this->assertEquals([], $this->auth->getUserIdsByRole('nonexisting'));
    }

    public function testCanAddChild(): void
    {
        $this->prepareData();

        $author = new Role('author');
        $reader = new Role('reader');

        $this->assertTrue($this->auth->canAddChild($author, $reader));
        $this->assertFalse($this->auth->canAddChild($reader, $author));
    }

    public function testCanNotAddRoleToPermission(): void
    {
        $permission = new Permission('test_permission');
        $role = new Role('test_role');

        $this->assertFalse($this->auth->canAddChild($permission, $role));
        $this->assertTrue($this->auth->canAddChild($role, $permission));
    }

    public function testRemoveAllRules(): void
    {
        $this->prepareData();

        $this->auth->removeAllRules();

        $this->assertEmpty($this->auth->getRules());

        $this->assertNotEmpty($this->auth->getRoles());
        $this->assertNotEmpty($this->auth->getPermissions());
    }

    public function testRemoveAllRoles(): void
    {
        $this->prepareData();

        $this->auth->removeAllRoles();

        $this->assertEmpty($this->auth->getRoles());

        $this->assertNotEmpty($this->auth->getRules());
        $this->assertNotEmpty($this->auth->getPermissions());
    }

    public function testRemoveAllPermissions(): void
    {
        $this->prepareData();

        $this->auth->removeAllPermissions();

        $this->assertEmpty($this->auth->getPermissions());

        $this->assertNotEmpty($this->auth->getRules());
        $this->assertNotEmpty($this->auth->getRoles());
    }

    public function testAssignRuleToRoleByName(): void
    {
        $userId = '3';
        $auth = $this->auth;
        $auth->removeAll();

        $rule = new ActionRule();
        $auth->add($rule);

        $role = (new Role('Reader'))
            ->withRuleName($rule->getName());
        $auth->add($role);

        $permission = new Permission('manage');
        $auth->add($permission);
        $auth->addChild($role, $permission);

        $auth->assign($role, $userId);

        $this->assertTrue($auth->userHasPermission($userId, 'manage', ['action' => 'read']));
        $this->assertFalse($auth->userHasPermission($userId, 'manage', ['action' => 'write']));
    }

    public function testAssignRuleToPermissionByName(): void
    {
        $userId = '3';
        $auth = $this->auth;
        $auth->removeAll();
        $rule = new ActionRule();
        $auth->add($rule);
        $item = (new Permission('manage'))
            ->withRuleName($rule->getName());
        $auth->add($item);

        $auth->assign($item, $userId);

        $this->assertTrue($auth->userHasPermission($userId, 'manage', ['action' => 'read']));
        $this->assertFalse($auth->userHasPermission($userId, 'manage', ['action' => 'write']));
    }

    public function testUpdateRoleNameAndRule(): void
    {
        $userId = '3';
        $auth = $this->auth;
        $auth->removeAll();

        $auth->add(new ActionRule());
        $auth->add(new AuthorRule());

        $role = (new Role('Reader'))
            ->withRuleName('action_rule');
        $auth->add($role);
        $auth->assign($role, $userId);

        $permission = new Permission('manage');
        $auth->add($permission);
        $auth->addChild($role, $permission);

        $role = $auth->getRole('Reader')
            ->withName('AdminPost')
            ->withRuleName('isAuthor');
        $auth->update('Reader', $role);

        $this->assertArrayNotHasKey(
            'Reader',
            $auth->getRolesByUser($userId),
            'Old role should not be assigned'
        );

        $this->assertArrayHasKey(
            'AdminPost',
            $auth->getRolesByUser($userId),
            'New role should be assigned'
        );

        $role = $auth->getRole('AdminPost');
        $this->assertSame('isAuthor', $role->getRuleName(), 'Rule should have new name');
    }

    public function testUpdatePermissionNameAndRule(): void
    {
        $userId = '3';
        $auth = $this->auth;
        $auth->removeAll();

        $auth->add(new ActionRule());
        $auth->add(new AuthorRule());

        $manage = (new Permission('manage'))
            ->withRuleName('action_rule');
        $auth->add($manage);
        $auth->assign($manage, $userId);

        $manage = $auth->getPermission('manage')
            ->withName('admin')
            ->withRuleName('isAuthor');
        $auth->update('manage', $manage);

        $this->assertTrue($auth->userHasPermission($userId, 'admin', ['authorID' => 3]));
        $this->assertFalse($auth->userHasPermission($userId, 'manage', ['authorID' => 3]));
    }

    public function testRevokeRole(): void
    {
        $userId = '3';
        $auth = $this->auth;
        $auth->removeAll();

        $role = new Role('Admin');
        $auth->add($role);
        $auth->assign($role, $userId);
        $auth->revoke($role, $userId);

        $this->assertNotContains('Admin', $auth->getRolesByUser($userId));
    }

    public function testRevokePermission(): void
    {
        $userId = '3';
        $auth = $this->auth;
        $auth->removeAll();

        $permission = new Permission('manage');
        $auth->add($permission);
        $auth->assign($permission, $userId);
        $auth->revoke($permission, $userId);

        $this->assertFalse($auth->userHasPermission($userId, 'manage'));
    }

    public function testRevokePermissionWithRule(): void
    {
        $userId = '3';
        $auth = $this->auth;
        $auth->removeAll();

        $rule = new ActionRule();
        $auth->add($rule);

        $permission = (new Permission('manage'))
            ->withRuleName($rule->getName());
        $auth->add($permission);
        $auth->assign($permission, $userId);

        $auth->revoke($permission, $userId);

        $this->assertFalse($auth->userHasPermission($userId, 'manage', ['action' => 'read']));
        $this->assertFalse($auth->userHasPermission($userId, 'manage', ['action' => 'write']));
    }

    public function testRevokeRoleWithRule(): void
    {
        $userId = '3';
        $auth = $this->auth;
        $auth->removeAll();

        $rule = new ActionRule();
        $auth->add($rule);

        $role = (new Role('Admin'))
            ->withRuleName($rule->getName());
        $auth->add($role);
        $auth->assign($role, $userId);

        $auth->revoke($role, $userId);

        $this->assertFalse($auth->userHasPermission($userId, 'Admin', ['action' => 'read']));
        $this->assertFalse($auth->userHasPermission($userId, 'Admin', ['action' => 'write']));
    }

    /**
     * @see https://github.com/yiisoft/yii2/issues/10176
     * @see https://github.com/yiisoft/yii2/issues/12681
     */
    public function testRuleWithPrivateFields(): void
    {
        $auth = $this->auth;

        $auth->removeAll();

        $rule = new ActionRule();
        $auth->add($rule);

        /** @var ActionRule $rule */
        $rule = $this->auth->getRule('action_rule');
        $this->assertInstanceOf(ActionRule::class, $rule);
    }

    public function testDefaultRolesWithClosureReturningNonArrayValue(): void
    {
        $this->expectException(InvalidValueException::class);
        $this->expectExceptionMessage('Default roles closure must return an array');
        $this->auth->setDefaultRoles(
            static function () {
                return 'test';
            }
        );
    }

    public function testDefaultRolesWithNonArrayValue(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Default roles must be either an array or a callable');
        $this->auth->setDefaultRoles('test');
    }

    public function testUpdateRule(): void
    {
        $this->prepareData();

        $rule = $this->auth->getRule('isAuthor');
        $rule = $rule
            ->withName('newName')
            ->withReallyReally(false);

        $this->auth->update('isAuthor', $rule);

        $rule = $this->auth->getRule('isAuthor');
        $this->assertNull($rule);

        /** @var AuthorRule $rule */
        $rule = $this->auth->getRule('newName');
        $this->assertEquals('newName', $rule->getName());
        $this->assertFalse($rule->isReallyReally());

        $rule = $rule->withReallyReally(true);
        $this->auth->update('newName', $rule);

        /** @var AuthorRule $rule */
        $rule = $this->auth->getRule('newName');
        $this->assertTrue($rule->isReallyReally());

        $item = $this->auth->getPermission('createPost')
            ->withName('new createPost');
        $this->auth->update('createPost', $item);

        $item = $this->auth->getPermission('createPost');
        $this->assertNull($item);

        $item = $this->auth->getPermission('new createPost');
        $this->assertEquals('new createPost', $item->getName());
    }

    public function testUpdateItemName(): void
    {
        $this->prepareData();

        $name = 'readPost';
        $permission = $this->auth->getPermission($name);
        $permission = $permission->withName('UPDATED-NAME');
        $this->auth->update($name, $permission);

        $this->assertNull($this->auth->getPermission('readPost'));
        $this->assertNotNull($this->auth->getPermission('UPDATED-NAME'));
    }

    public function testUpdateDescription(): void
    {
        $this->prepareData();
        $name = 'readPost';
        $permission = $this->auth->getPermission($name);
        $newDescription = 'UPDATED-DESCRIPTION';
        $permission = $permission->withDescription($newDescription);
        $this->auth->update($name, $permission);

        $permission = $this->auth->getPermission('readPost');
        $this->assertEquals($newDescription, $permission->getDescription());
    }

    public function testOverwriteName(): void
    {
        $this->prepareData();
        $name = 'readPost';
        $permission = $this->auth->getPermission($name);
        $permission = $permission->withName('createPost');
        $this->expectException(InvalidArgumentException::class);
        $this->auth->update($name, $permission);
    }

    protected function tearDown(): void
    {
        FileHelper::removeDirectory($this->testDataPath);
        static::$filemtime = null;
        parent::tearDown();
        $this->auth->removeAll();
        static::$time = null;
    }

    protected function setUp(): void
    {
        static::$filemtime = null;
        $this->testDataPath = sys_get_temp_dir() . '/' . str_replace('\\', '_', get_class($this)) . uniqid('', false);
        if (FileHelper::createDirectory($this->testDataPath) === false) {
            throw new \RuntimeException('Unable to create directory: ' . $this->testDataPath);
        }

        parent::setUp();
        $this->createManager();
        static::$time = null;
    }

    private function getAssignmentFilePath(): string
    {
        return $this->testDataPath . '/assignments.php';
    }

    private function createManager(): void
    {
        $this->storage = new ExponsedPhpStorage($this->testDataPath);
        $this->auth = (new PhpManager(
            $this->storage,
            new ClassNameRuleFactory()
        ))->setDefaultRoles(['myDefaultRole']);
    }

    /**
     * See hierarchy.png in tests directory for a quick overview
     *
     * @throws \Exception
     */
    private function prepareData(): void
    {
        $rule = new AuthorRule();
        $this->auth->add($rule);

        $uniqueTrait = (new Permission('Fast Metabolism'))
            ->withDescription(
                'Your metabolic rate is twice normal. This means that you are much less resistant to radiation and poison, but your body heals faster.'
            );
        $this->auth->add($uniqueTrait);

        $createPost = (new Permission('createPost'))
            ->withDescription('create a post');
        // FIXME: $createPost->data = 'createPostData';
        $this->auth->add($createPost);

        $readPost = (new Permission('readPost'))
            ->withDescription('read a post');
        $this->auth->add($readPost);

        $deletePost = (new Permission('deletePost'))
            ->withDescription('delete a post');
        $this->auth->add($deletePost);

        $updatePost = (new Permission('updatePost'))
            ->withDescription('update a post')
            ->withRuleName($rule->getName());
        $this->auth->add($updatePost);

        $updateAnyPost = (new Permission('updateAnyPost'))
            ->withDescription('update any post');
        $this->auth->add($updateAnyPost);

        $withoutChildren = new Role('withoutChildren');
        $this->auth->add($withoutChildren);

        $reader = new Role('reader');
        $this->auth->add($reader);
        $this->auth->addChild($reader, $readPost);

        $author = new Role('author');
        // FIXME: $author->data = 'authorData';
        $this->auth->add($author);
        $this->auth->addChild($author, $createPost);
        $this->auth->addChild($author, $updatePost);
        $this->auth->addChild($author, $reader);

        $admin = new Role('admin');
        $this->auth->add($admin);
        $this->auth->addChild($admin, $author);
        $this->auth->addChild($admin, $updateAnyPost);

        $this->auth->assign($uniqueTrait, 'reader A');

        $this->auth->assign($reader, 'reader A');
        $this->auth->assign($author, 'author B');
        $this->auth->assign($deletePost, 'author B');
        $this->auth->assign($admin, 'admin C');
    }

    private function getCustomItem(): ItemInterface
    {
        return new class() implements ItemInterface {
            public function getName(): string
            {
                return 'custom item';
            }

            public function getAttributes(): array
            {
                return [
                    'name' => $this->getName()
                ];
            }
        };
    }
}
