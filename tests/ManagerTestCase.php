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

abstract class ManagerTestCase extends TestCase
{
    /**
     * @var ManagerInterface|BaseManager
     */
    protected $auth;

    protected function setUp(): void
    {
        parent::setUp();
        $this->auth = $this->createManager();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        $this->auth->removeAll();
    }

    abstract protected function createManager(): ManagerInterface;

    public function testCreateRole(): void
    {
        $role = $this->auth->createRole('admin');
        $this->assertInstanceOf(Role::class, $role);
        $this->assertEquals(Item::TYPE_ROLE, $role->getType());
        $this->assertEquals('admin', $role->getName());
    }

    public function testCreatePermission(): void
    {
        $permission = $this->auth->createPermission('edit post');
        $this->assertInstanceOf(Permission::class, $permission);
        $this->assertEquals(Item::TYPE_PERMISSION, $permission->getType());
        $this->assertEquals('edit post', $permission->getName());
    }

    public function testAdd(): void
    {
        $role = $this->auth->createRole('admin');
        $role = $role->withDescription('administrator');
        $this->auth->add($role);
        $this->assertNotNull($this->auth->getRole('admin'));

        $permission = $this->auth->createPermission('edit post');
        $permission = $permission->withDescription('edit a post');
        $this->auth->add($permission);
        $this->assertNotNull($this->auth->getPermission('edit post'));

        $rule = new AuthorRule('is author', true);
        $this->auth->add($rule);
        $this->assertNotNull($this->auth->getRule('is author'));
        // todo: check duplication of name
    }

    public function testGetChildren(): void
    {
        $user = $this->auth->createRole('user');
        $this->auth->add($user);
        $this->assertCount(0, $this->auth->getChildren($user->getName()));

        $changeName = $this->auth->createPermission('changeName');
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

    public function testHasPermission(): void
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
                $this->assertEquals($result, $this->auth->hasPermission($user, $permission, $params), "Checking $user can $permission");
            }
        }
    }

    protected function prepareData(): void
    {
        $rule = new AuthorRule();
        $this->auth->add($rule);

        $uniqueTrait = $this->auth->createPermission('Fast Metabolism')
            ->withDescription('Your metabolic rate is twice normal. This means that you are much less resistant to radiation and poison, but your body heals faster.');
        $this->auth->add($uniqueTrait);

        $createPost = $this->auth->createPermission('createPost')
            ->withDescription('create a post');
        // FIXME: $createPost->data = 'createPostData';
        $this->auth->add($createPost);

        $readPost = $this->auth->createPermission('readPost')
            ->withDescription('read a post');
        $this->auth->add($readPost);

        $deletePost = $this->auth->createPermission('deletePost')
            ->withDescription('delete a post');
        $this->auth->add($deletePost);

        $updatePost = $this->auth->createPermission('updatePost')
            ->withDescription('update a post')
            ->withRuleName($rule->getName());
        $this->auth->add($updatePost);

        $updateAnyPost = $this->auth->createPermission('updateAnyPost')
            ->withDescription('update any post');
        $this->auth->add($updateAnyPost);

        $withoutChildren = $this->auth->createRole('withoutChildren');
        $this->auth->add($withoutChildren);

        $reader = $this->auth->createRole('reader');
        $this->auth->add($reader);
        $this->auth->addChild($reader, $readPost);

        $author = $this->auth->createRole('author');
        // FIXME: $author->data = 'authorData';
        $this->auth->add($author);
        $this->auth->addChild($author, $createPost);
        $this->auth->addChild($author, $updatePost);
        $this->auth->addChild($author, $reader);

        $admin = $this->auth->createRole('admin');
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

        $author = $this->auth->createRole('author');
        $reader = $this->auth->createRole('reader');

        $this->assertTrue($this->auth->canAddChild($author, $reader));
        $this->assertFalse($this->auth->canAddChild($reader, $author));
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
    public function testAssignRule(string $RBACItemType): void
    {
        $auth = $this->auth;
        $userId = 3;

        $auth->removeAll();
        $item = $this->createRBACItem($RBACItemType, 'Admin');
        $auth->add($item);

        $auth->assign($item, $userId);

        $this->assertTrue($auth->hasPermission($userId, 'Admin'));

        // with normal register rule
        $auth->removeAll();
        $rule = new ActionRule();
        $auth->add($rule);
        $item = $this->createRBACItem($RBACItemType, 'Reader')
            ->withRuleName($rule->getName());
        $auth->add($item);
        $auth->assign($item, $userId);

        $this->assertTrue($auth->hasPermission($userId, 'Reader', ['action' => 'read']));
        $this->assertFalse($auth->hasPermission($userId, 'Reader', ['action' => 'write']));

        // using rule class name
        $auth->removeAll();
        $item = $this->createRBACItem($RBACItemType, 'Reader')
            ->withRuleName(ActionRule::class);
        $auth->add($item);
        $auth->assign($item, $userId);

        $this->assertTrue($auth->hasPermission($userId, 'Reader', ['action' => 'read']));
        $this->assertFalse($auth->hasPermission($userId, 'Reader', ['action' => 'write']));

        // using DI
        $this->container->set('write_rule', ['__class' => ActionRule::class, 'action' => 'write']);
        $this->container->set('delete_rule', ['__class' => ActionRule::class, 'action' => 'delete']);
        $this->container->set('all_rule', ['__class' => ActionRule::class, 'action' => 'all']);

        $item = $this->createRBACItem($RBACItemType, 'Writer')
            ->withRuleName('write_rule');
        $auth->add($item);
        $auth->assign($item, $userId);
        $this->assertTrue($auth->hasPermission($userId, 'Writer', ['action' => 'write']));
        $this->assertFalse($auth->hasPermission($userId, 'Writer', ['action' => 'update']));

        $item = $this->createRBACItem($RBACItemType, 'Deleter')
            ->withRuleName('delete_rule');
        $auth->add($item);
        $auth->assign($item, $userId);
        $this->assertTrue($auth->hasPermission($userId, 'Deleter', ['action' => 'delete']));
        $this->assertFalse($auth->hasPermission($userId, 'Deleter', ['action' => 'update']));

        $item = $this->createRBACItem($RBACItemType, 'Author')
            ->withRuleName('all_rule');
        $auth->add($item);
        $auth->assign($item, $userId);
        $this->assertTrue($auth->hasPermission($userId, 'Author', ['action' => 'update']));

        // update role and rule
        $item = $this->getRBACItem($RBACItemType, 'Reader')
            ->withName('AdminPost')
            ->withRuleName('all_rule');
        $auth->update('Reader', $item);
        $this->assertTrue($auth->hasPermission($userId, 'AdminPost', ['action' => 'print']));
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
        $this->assertFalse($auth->hasPermission($userId, 'Admin'));

        $auth->removeAll();
        $rule = new ActionRule();
        $auth->add($rule);
        $item = $this->createRBACItem($RBACItemType, 'Reader')
            ->withRuleName($rule->getName());
        $auth->add($item);

        $auth->assign($item, $userId);

        $auth->revoke($item, $userId);
        $this->assertFalse($auth->hasPermission($userId, 'Reader', ['action' => 'read']));
        $this->assertFalse($auth->hasPermission($userId, 'Reader', ['action' => 'write']));
    }

    /**
     * Create Role or Permission RBAC item.
     *
     * @param int    $RBACItemType
     * @param string $name
     *
     * @return Permission|Role
     */
    private function createRBACItem($RBACItemType, $name)
    {
        if ($RBACItemType === Item::TYPE_ROLE) {
            return $this->auth->createRole($name);
        }
        if ($RBACItemType === Item::TYPE_PERMISSION) {
            return $this->auth->createPermission($name);
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
}
