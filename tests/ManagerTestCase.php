<?php
namespace Yiisoft\Rbac\Tests;

use PHPUnit\Framework\TestCase;
use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\Manager\BaseManager;
use Yiisoft\Rbac\ManagerInterface;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\Role;
use Yiisoft\Rbac\Exceptions\InvalidArgumentException;
use Yiisoft\Rbac\Exceptions\InvalidValueException;
use Yiisoft\Rbac\Rule;

/**
 * Mock for the time() function for RBAC classes. Avoid random test fails.
 *
 * @return int
 */
function time()
{
    return \Yiisoft\Rbac\Tests\PhpManagerTest::$time ?: \time();
}

abstract class ManagerTestCase extends TestCase
{
    public static $time;

    /**
     * @var ManagerInterface|BaseManager
     */
    protected $auth;

    protected function setUp(): void
    {
        parent::setUp();
        $this->auth = $this->createManager();
        static::$time = null;
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        $this->auth->removeAll();
        static::$time = null;
    }

    abstract protected function createManager(): ManagerInterface;

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

        $rule = $this->auth->getRule('nonExisting');
        $this->assertNull($rule);
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
                'blablabla' => false,
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
                $this->assertEquals($result, $this->auth->userHasPermission($user, $permission, $params), "Checking $user can $permission");
            }
        }
    }

    /**
     * See hierarchy.png in tests directory for a quick overview
     *
     * @throws \Exception
     */
    protected function prepareData(): void
    {
        $rule = new AuthorRule();
        $this->auth->add($rule);

        $uniqueTrait = (new Permission('Fast Metabolism'))
            ->withDescription('Your metabolic rate is twice normal. This means that you are much less resistant to radiation and poison, but your body heals faster.');
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
        // FIXME: $this->assertEquals('authorData', $author->data);
    }

    public function testGetPermission(): void
    {
        $this->prepareData();
        $createPost = $this->auth->getPermission('createPost');
        $this->assertEquals(Item::TYPE_PERMISSION, $createPost->getType());
        $this->assertEquals('createPost', $createPost->getName());
        // FIXME: $this->assertEquals('createPostData', $createPost->data);
    }

    public function testGetRolesByUser(): void
    {
        $this->prepareData();
        $reader = $this->auth->getRole('reader');
        $this->auth->assign($reader, 0);
        $this->auth->assign($reader, 123);

        $roles = $this->auth->getRolesByUser('reader A');
        $this->assertInstanceOf(Role::class, reset($roles));
        $this->assertEquals($roles['reader']->getName(), 'reader');

        $roles = $this->auth->getRolesByUser(0);
        $this->assertInstanceOf(Role::class, reset($roles));
        $this->assertEquals($roles['reader']->getName(), 'reader');

        $roles = $this->auth->getRolesByUser(123);
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

        $this->auth = $this->createManager();
//        $this->auth->load();

        $roles = $this->auth->getRolesByUser('readingAuthor');
        $roleNames = [];
        foreach ($roles as $role) {
            $roleNames[] = $role->getName();
        }

        $this->assertContains('reader', $roleNames,
            'Roles should contain reader. Currently it has: ' . implode(', ', $roleNames));
        $this->assertContains('author', $roleNames,
            'Roles should contain author. Currently it has: ' . implode(', ', $roleNames));
    }

    public function testAssignmentsToIntegerId(): void
    {
        $this->prepareData();

        $reader = $this->auth->getRole('reader');
        $author = $this->auth->getRole('author');
        $this->auth->assign($reader, 42);
        $this->auth->assign($author, 1337);
        $this->auth->assign($reader, 1337);

        $this->auth = $this->createManager();
        // $this->auth->load();

        $this->assertCount(0, $this->auth->getAssignments(0));
        $this->assertCount(1, $this->auth->getAssignments(42));
        $this->assertCount(2, $this->auth->getAssignments(1337));
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
        $this->auth->assign($admin, 1);

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
        $reader = $this->auth->getRole('reader');
        $this->auth->assign($reader, 123);

        $this->auth = $this->createManager();
        //$this->auth->load();

        $this->assertEquals([], $this->auth->getUserIdsByRole('nonexisting'));
        $this->assertEqualsCanonicalizing(['reader A', '123'], $this->auth->getUserIdsByRole('reader'), '');
        $this->assertEquals(['author B'], $this->auth->getUserIdsByRole('author'));
        $this->assertEquals(['admin C'], $this->auth->getUserIdsByRole('admin'));
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

    public function RBACItemsProvider(): array
    {
        return [
            [Item::TYPE_ROLE],
            [Item::TYPE_PERMISSION],
        ];
    }

    /**
     * @dataProvider RBACItemsProvider
     *
     * @param string $RBACItemType
     * @throws \Exception
     */
    public function testAssignRuleByName(string $RBACItemType): void
    {
        $userId = 3;
        $auth = $this->auth;
        $auth->removeAll();
        $rule = new ActionRule();
        $auth->add($rule);
        $item = $this->createRBACItem($RBACItemType, 'Reader')
            ->withRuleName($rule->getName());
        $auth->add($item);

        $auth->assign($item, $userId);

        $this->assertTrue($auth->userHasPermission($userId, 'Reader', ['action' => 'read']));
        $this->assertFalse($auth->userHasPermission($userId, 'Reader', ['action' => 'write']));
    }

    /**
     * @dataProvider RBACItemsProvider
     *
     * @param string $RBACItemType
     * @throws \Exception
     */
    public function testUpdateRoleAndRule(string $RBACItemType): void
    {
        $userId = 3;
        $auth = $this->auth;
        $auth->removeAll();

        $auth->add(new ActionRule());
        $auth->add(new AuthorRule());

        $reader = $this->createRBACItem($RBACItemType, 'Reader')
            ->withRuleName('action_rule');
        $auth->add($reader);
        $auth->assign($reader, $userId);

        $reader = $this->getRBACItem($RBACItemType, 'Reader')
            ->withName('AdminPost')
            ->withRuleName('isAuthor');
        $auth->update('Reader', $reader);

        $this->assertTrue($auth->userHasPermission($userId, 'AdminPost', ['authorID' => 3]));
        $this->assertFalse($auth->userHasPermission($userId, 'Reader', ['authorID' => 3]));
    }

    /**
     * @dataProvider RBACItemsProvider
     *
     * @param string $RBACItemType
     */
    public function testRevokeRule(string $RBACItemType): void
    {
        $userId = 3;
        $auth = $this->auth;

        $auth->removeAll();
        $item = $this->createRBACItem($RBACItemType, 'Admin');
        $auth->add($item);

        $auth->assign($item, $userId);

        $auth->revoke($item, $userId);
        $this->assertFalse($auth->userHasPermission($userId, 'Admin'));

        $auth->removeAll();
        $rule = new ActionRule();
        $auth->add($rule);
        $item = $this->createRBACItem($RBACItemType, 'Reader')
            ->withRuleName($rule->getName());
        $auth->add($item);

        $auth->assign($item, $userId);

        $auth->revoke($item, $userId);
        $this->assertFalse($auth->userHasPermission($userId, 'Reader', ['action' => 'read']));
        $this->assertFalse($auth->userHasPermission($userId, 'Reader', ['action' => 'write']));
    }

    /**
     * Create Role or Permission RBAC item.
     *
     * @param int $RBACItemType
     * @param string $name
     *
     * @return Permission|Role
     */
    private function createRBACItem($RBACItemType, $name)
    {
        if ($RBACItemType === Item::TYPE_ROLE) {
            return new Role($name);
        }
        if ($RBACItemType === Item::TYPE_PERMISSION) {
            return new Permission($name);
        }

        throw new \InvalidArgumentException();
    }

    /**
     * Get Role or Permission RBAC item.
     *
     * @param int    $RBACItemType
     * @param string $name
     *
     * @return Permission|Role
     */
    private function getRBACItem($RBACItemType, $name)
    {
        if ($RBACItemType === Item::TYPE_ROLE) {
            return $this->auth->getRole($name);
        }
        if ($RBACItemType === Item::TYPE_PERMISSION) {
            return $this->auth->getPermission($name);
        }

        throw new \InvalidArgumentException();
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
        $this->auth->setDefaultRoles(static function () {
            return 'test';
        });
    }

    public function testDefaultRolesWithNonArrayValue(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Default roles must be either an array or a callable');
        $this->auth->setDefaultRoles('test');
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
}
