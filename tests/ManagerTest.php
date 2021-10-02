<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Yiisoft\Rbac\Manager;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\Role;
use Yiisoft\Rbac\RuleFactory\ClassNameRuleFactory;
use Yiisoft\Rbac\StorageInterface;

/**
 * @group rbac
 */
class ManagerTest extends TestCase
{
    protected Manager $manager;

    protected StorageInterface $storage;

    protected function setUp(): void
    {
        parent::setUp();
        $this->storage = $this->createStorage();
        $this->manager = $this->createManager($this->storage);
    }

    /**
     * @dataProvider dataProviderUserHasPermission
     */
    public function testUserHasPermission($user, array $tests): void
    {
        $manager = $this->manager;

        $params = ['authorID' => 'author B'];

        foreach ($tests as $permission => $result) {
            $this->assertEquals(
                $result,
                $manager->userHasPermission($user, $permission, $params),
                "Checking \"$user\" can \"$permission\""
            );
        }
    }

    public function dataProviderUserHasPermission(): array
    {
        return [
            [
                'reader A',
                [
                    'createPost' => false,
                    'readPost' => true,
                    'updatePost' => false,
                    'updateAnyPost' => false,
                    'reader' => false,
                ],
            ],
            [
                'author B',
                [
                    'createPost' => true,
                    'readPost' => true,
                    'updatePost' => true,
                    'deletePost' => true,
                    'updateAnyPost' => false,
                ]
            ],
            [
                'admin C',
                [
                    'createPost' => true,
                    'readPost' => true,
                    'updatePost' => false,
                    'updateAnyPost' => true,
                    'nonExistingPermission' => false,
                    null => false,
                ],
            ],
            [
                'guest',
                [
                    'createPost' => false,
                    'readPost' => false,
                    'updatePost' => false,
                    'deletePost' => false,
                    'updateAnyPost' => false,
                    'blablabla' => false,
                    null => false,
                ]
            ],
            [
                12,
                [
                    'createPost' => false,
                    'readPost' => false,
                    'updatePost' => false,
                    'deletePost' => false,
                    'updateAnyPost' => false,
                    'blablabla' => false,
                    null => false,
                ]
            ],
        ];
    }

    /**
     * @dataProvider dataProviderUserHasPermissionWithFailUserId
     */
    public function testUserHasPermissionWithFailUserId($userId): void
    {
        $this->expectException(InvalidArgumentException::class);

        $manager = $this->manager;

        $permission = 'createPost';
        $params = ['authorID' => 'author B'];

        $manager->userHasPermission($userId, $permission, $params);
    }

    public function dataProviderUserHasPermissionWithFailUserId(): array
    {
        return [
            [true],
            [null],
            [['test' => 1]],
        ];
    }

    public function testUserHasPermissionReturnFalseForNonExistingUserAndNoDefaultRoles(): void
    {
        $manager = $this->manager;
        $manager->setDefaultRoles([]);
        $this->assertFalse($manager->userHasPermission('unknown user', 'createPost'));
    }

    public function testCanAddChildReturnTrue(): void
    {
        $manager = $this->manager;

        $this->assertTrue(
            $manager->canAddChild(
                new Role('author'),
                new Role('reader')
            )
        );
    }

    public function testCanAddChildDetectLoop(): void
    {
        $manager = $this->manager;

        $this->assertFalse(
            $manager->canAddChild(
                new Role('reader'),
                new Role('author')
            )
        );
    }

    public function testCanAddChildPermissionToRole(): void
    {
        $manager = $this->manager;
        $this->assertFalse(
            $manager->canAddChild(
                new Permission('test_permission'),
                new Role('test_role')
            )
        );
    }

    public function testAddChild(): void
    {
        $storage = $this->storage;
        $manager = $this->manager;

        $manager->addChild(
            $storage->getRoleByName('reader'),
            $storage->getPermissionByName('createPost')
        );

        $this->assertEquals(
            [
                'readPost',
                'createPost',
            ],
            array_keys($storage->getChildrenByName('reader'))
        );
    }

    public function testAddChildNotHasItem(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Either "new reader" does not exist.');

        $storage = $this->storage;
        $manager = $this->manager;

        $manager->addChild(
            new Role('new reader'),
            $storage->getPermissionByName('createPost')
        );
    }

    public function testAddChildEqualName(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot add "createPost" as a child of itself.');

        $storage = $this->storage;
        $manager = $this->manager;

        $manager->addChild(
            new Role('createPost'),
            $storage->getPermissionByName('createPost')
        );
    }

    public function testAddChildPermissionToRole(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Can not add "reader" role as a child of "createPost" permission.');

        $storage = $this->storage;
        $manager = $this->manager;

        $manager->addChild(
            $storage->getPermissionByName('createPost'),
            $storage->getRoleByName('reader')
        );
    }

    public function testAddChildAlreadyAdded(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The item "reader" already has a child "readPost".');

        $storage = $this->storage;
        $manager = $this->manager;

        $manager->addChild(
            $storage->getRoleByName('reader'),
            $storage->getPermissionByName('readPost')
        );
    }

    public function testAddChildDetectLoop(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Cannot add "author" as a child of "reader". A loop has been detected.');

        $storage = $this->storage;
        $manager = $this->manager;

        $manager->addChild(
            $storage->getRoleByName('reader'),
            $storage->getRoleByName('author'),
        );
    }

    public function testRemoveChild(): void
    {
        $storage = $this->storage;
        $manager = $this->manager;

        $manager->removeChild(
            $storage->getRoleByName('author'),
            $storage->getPermissionByName('createPost'),
        );

        $this->assertEquals(
            [
                'updatePost',
                'reader',
            ],
            array_keys($storage->getChildrenByName('author'))
        );
    }

    public function testRemoveChildren(): void
    {
        $storage = $this->storage;
        $manager = $this->manager;
        $author = $storage->getRoleByName('author');

        $manager->removeChildren($author);
        $this->assertFalse($storage->hasChildren('author'));
    }

    public function testHasChild(): void
    {
        $storage = $this->storage;
        $manager = $this->manager;

        $author = $storage->getRoleByName('author');
        $reader = $storage->getRoleByName('reader');
        $permission = $storage->getPermissionByName('createPost');

        $this->assertTrue($manager->hasChild($author, $permission));
        $this->assertFalse($manager->hasChild($reader, $permission));
    }

    public function testAssign(): void
    {
        $storage = $this->storage;
        $manager = $this->manager;

        $manager->assign(
            $storage->getRoleByName('reader'),
            'readingAuthor'
        );
        $manager->assign(
            $storage->getRoleByName('author'),
            'readingAuthor'
        );

        $this->assertEquals(
            [
                'myDefaultRole',
                'reader',
                'author',
            ],
            array_keys($manager->getRolesByUser('readingAuthor'))
        );
    }

    public function testAssignUnknownItem(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unknown role "nonExistRole".');
        $manager = $this->manager;

        $manager->assign(
            new Role('nonExistRole'),
            'reader'
        );
    }

    public function testAssignAlreadyAssignedItem(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('"reader" role has already been assigned to user reader A.');

        $storage = $this->storage;
        $manager = $this->manager;

        $manager->assign(
            $storage->getRoleByName('reader'),
            'reader A'
        );
    }

    public function testRevokeRole(): void
    {
        $storage = $this->storage;
        $manager = $this->manager;

        $manager->revoke(
            $storage->getRoleByName('reader'),
            'reader A'
        );

        $this->assertEquals(['Fast Metabolism'], array_keys($storage->getUserAssignments('reader A')));
    }

    public function testRevokePermission(): void
    {
        $storage = $this->storage;
        $manager = $this->manager;

        $manager->revoke(
            $storage->getPermissionByName('deletePost'),
            'author B'
        );

        $this->assertEquals(['author'], array_keys($storage->getUserAssignments('author B')));
    }

    public function testRevokeAll(): void
    {
        $storage = $this->storage;
        $manager = $this->manager;

        $manager->revokeAll('author B');
        $this->assertEmpty($storage->getUserAssignments('author B'));
    }

    public function testGetRolesByUser(): void
    {
        $manager = $this->manager;

        $this->assertEquals(
            ['myDefaultRole', 'reader'],
            array_keys($manager->getRolesByUser('reader A'))
        );
    }

    public function testGetChildRoles(): void
    {
        $manager = $this->manager;

        $this->assertEquals(
            ['admin', 'reader', 'author'],
            array_keys($manager->getChildRoles('admin'))
        );
    }

    public function testGetChildRolesUnknownRole(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Role "unknown" not found.');

        $manager = $this->manager;
        $manager->getChildRoles('unknown');
    }

    public function testGetPermissionsByRole(): void
    {
        $manager = $this->manager;

        $this->assertEquals(
            ['createPost', 'updatePost', 'readPost', 'updateAnyPost'],
            array_keys($manager->getPermissionsByRole('admin'))
        );

        $this->assertEmpty($manager->getPermissionsByRole('guest'));
    }

    public function testGetPermissionsByUser(): void
    {
        $manager = $this->manager;

        $this->assertEquals(
            ['deletePost', 'createPost', 'updatePost', 'readPost'],
            array_keys($manager->getPermissionsByUser('author B'))
        );
    }

    public function testUserIdsByRole(): void
    {
        $manager = $this->manager;

        $this->assertEquals(
            [
                'reader A',
                'author B',
                'admin C',
            ],
            $manager->getUserIdsByRole('reader')
        );
        $this->assertEquals(
            [
                'author B',
                'admin C',
            ],
            $manager->getUserIdsByRole('author')
        );
        $this->assertEquals(['admin C'], $manager->getUserIdsByRole('admin'));
    }

    public function testAddRole(): void
    {
        $storage = $this->storage;
        $manager = $this->manager;

        $rule = new EasyRule();

        $role = (new Role('new role'))
            ->withDescription('new role description')
            ->withRuleName($rule->getName());

        $manager->addRole($role);
        $this->assertNotNull($storage->getRoleByName('new role'));
    }

    public function testRemoveRole(): void
    {
        $storage = $this->storage;
        $manager = $this->manager;

        $manager->removeRole($storage->getRoleByName('reader'));
        $this->assertNull($storage->getRoleByName('new role'));
    }

    public function testUpdateRoleNameAndRule(): void
    {
        $storage = $this->storage;
        $manager = $this->manager;

        $role = $storage->getRoleByName('reader')->withName('new reader');
        $manager->updateRole('reader', $role);

        $this->assertNull($storage->getRoleByName('reader'));
        $this->assertNotNull($storage->getRoleByName('new reader'));
    }

    public function testAddPermission(): void
    {
        $storage = $this->storage;
        $manager = $this->manager;

        $permission = (new Permission('edit post'))
            ->withDescription('edit a post');

        $manager->addPermission($permission);
        $this->assertNotNull($storage->getPermissionByName('edit post'));
    }

    public function testRemovePermission(): void
    {
        $storage = $this->storage;
        $manager = $this->manager;

        $manager->removePermission($storage->getPermissionByName('updatePost'));
        $this->assertNull($storage->getPermissionByName('updatePost'));
    }

    public function testUpdatePermission(): void
    {
        $storage = $this->storage;
        $manager = $this->manager;

        $permission = $storage->getPermissionByName('updatePost')
            ->withName('newUpdatePost');

        $manager->updatePermission('updatePost', $permission);

        $this->assertNull($storage->getPermissionByName('updatePost'));
        $this->assertNotNull($storage->getPermissionByName('newUpdatePost'));
    }

    public function testUpdatePermissionNameAlreadyUsed(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Unable to change the item name. The name "createPost" is already used by another item.'
        );

        $storage = $this->storage;
        $manager = $this->manager;

        $permission = $storage->getPermissionByName('updatePost')
            ->withName('createPost');

        $manager->updatePermission('updatePost', $permission);
    }

    public function testAddRule(): void
    {
        $storage = $this->storage;
        $manager = $this->manager;

        $ruleName = 'isReallyReallyAuthor';
        $rule = new AuthorRule($ruleName, true);
        $manager->addRule($rule);

        $rule = $storage->getRuleByName($ruleName);
        $this->assertEquals($ruleName, $rule->getName());
        $this->assertTrue($rule->isReallyReally());
    }

    public function testRemoveRule(): void
    {
        $storage = $this->storage;
        $manager = $this->manager;

        $manager->removeRule(
            $storage->getRuleByName('isAuthor')
        );

        $this->assertNull($storage->getRuleByName('isAuthor'));
    }

    public function testUpdateRule(): void
    {
        $storage = $this->storage;
        $manager = $this->manager;

        $rule = $storage->getRuleByName('isAuthor')
            ->withName('newName')
            ->withReallyReally(false);

        $manager->updateRule('isAuthor', $rule);
        $this->assertNull($storage->getRuleByName('isAuthor'));
        $this->assertNotNull($storage->getRuleByName('newName'));
    }

    public function testDefaultRolesSetWithClosure(): void
    {
        $manager = $this->manager;

        $manager->setDefaultRoles(
            static function () {
                return ['newDefaultRole'];
            }
        );

        $this->assertEquals(['newDefaultRole'], $manager->getDefaultRoles());
    }

    public function testDefaultRolesWithClosureReturningNonArrayValue(): void
    {
        $manager = $this->manager;

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
        $manager = $this->manager;

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Default roles must be either an array or a closure');
        $manager->setDefaultRoles('test');
    }

    public function testGetDefaultRoles(): void
    {
        $manager = $this->manager;

        $this->assertEquals(['myDefaultRole'], $manager->getDefaultRoles());
    }

    protected function createManager(StorageInterface $storage): Manager
    {
        return (new Manager($storage, new ClassNameRuleFactory()))
            ->setDefaultRoles(['myDefaultRole']);
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

        $storage->addAssignment('reader A', new Permission('Fast Metabolism'));
        $storage->addAssignment('reader A', new Role('reader'));
        $storage->addAssignment('author B', new Role('author'));
        $storage->addAssignment('author B', new Permission('deletePost'));
        $storage->addAssignment('admin C', new Role('admin'));

        $storage->addRule(new AuthorRule('isAuthor'));

        return $storage;
    }
}
