<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Yiisoft\Rbac\AssignmentsStorageInterface;
use Yiisoft\Rbac\Manager;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\Role;
use Yiisoft\Rbac\RolesStorageInterface;
use Yiisoft\Rbac\RuleFactory\ClassNameRuleFactory;

/**
 * @group rbac
 */
final class ManagerTest extends TestCase
{
    private Manager $manager;

    private RolesStorageInterface $rolesStorage;

    private AssignmentsStorageInterface $assignmentsStorage;

    protected function setUp(): void
    {
        parent::setUp();
        $this->rolesStorage = $this->createRolesStorage();
        $this->assignmentsStorage = $this->createAssignmentsStorage();
        $this->manager = $this->createManager($this->rolesStorage, $this->assignmentsStorage);
    }

    /**
     * @dataProvider dataProviderUserHasPermission
     */
    public function testUserHasPermission($user, array $tests): void
    {
        $params = ['authorID' => 'author B'];

        foreach ($tests as $permission => $result) {
            $this->assertEquals(
                $result,
                $this->manager->userHasPermission($user, $permission, $params),
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
                ],
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
                ],
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
                ],
            ],
        ];
    }

    /**
     * @dataProvider dataProviderUserHasPermissionWithFailUserId
     */
    public function testUserHasPermissionWithFailUserId($userId): void
    {
        $this->expectException(InvalidArgumentException::class);

        $permission = 'createPost';
        $params = ['authorID' => 'author B'];

        $this->manager->userHasPermission($userId, $permission, $params);
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
        $this->manager->setDefaultRoles([]);
        $this->assertFalse($this->manager->userHasPermission('unknown user', 'createPost'));
    }

    public function testCanAddChildReturnTrue(): void
    {
        $this->assertTrue(
            $this->manager->canAddChild(
                new Role('author'),
                new Role('reader')
            )
        );
    }

    public function testCanAddChildDetectLoop(): void
    {
        $this->assertFalse(
            $this->manager->canAddChild(
                new Role('reader'),
                new Role('author')
            )
        );
    }

    public function testCanAddChildPermissionToRole(): void
    {
        $this->assertFalse(
            $this->manager->canAddChild(
                new Permission('test_permission'),
                new Role('test_role')
            )
        );
    }

    public function testAddChild(): void
    {
        $this->manager->addChild(
            $this->rolesStorage->getRoleByName('reader'),
            $this->rolesStorage->getPermissionByName('createPost')
        );

        $this->assertEquals(
            [
                'readPost',
                'createPost',
            ],
            array_keys($this->rolesStorage->getChildrenByName('reader'))
        );
    }

    public function testAddChildNotHasItem(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Either "new reader" does not exist.');

        $this->manager->addChild(
            new Role('new reader'),
            $this->rolesStorage->getPermissionByName('createPost')
        );
    }

    public function testAddChildEqualName(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot add "createPost" as a child of itself.');

        $this->manager->addChild(
            new Role('createPost'),
            $this->rolesStorage->getPermissionByName('createPost')
        );
    }

    public function testAddChildPermissionToRole(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Can not add "reader" role as a child of "createPost" permission.');

        $this->manager->addChild(
            $this->rolesStorage->getPermissionByName('createPost'),
            $this->rolesStorage->getRoleByName('reader')
        );
    }

    public function testAddChildAlreadyAdded(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The item "reader" already has a child "readPost".');

        $this->manager->addChild(
            $this->rolesStorage->getRoleByName('reader'),
            $this->rolesStorage->getPermissionByName('readPost')
        );
    }

    public function testAddChildDetectLoop(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Cannot add "author" as a child of "reader". A loop has been detected.');

        $this->manager->addChild(
            $this->rolesStorage->getRoleByName('reader'),
            $this->rolesStorage->getRoleByName('author'),
        );
    }

    public function testRemoveChild(): void
    {
        $this->manager->removeChild(
            $this->rolesStorage->getRoleByName('author'),
            $this->rolesStorage->getPermissionByName('createPost'),
        );

        $this->assertEquals(
            [
                'updatePost',
                'reader',
            ],
            array_keys($this->rolesStorage->getChildrenByName('author'))
        );
    }

    public function testRemoveChildren(): void
    {
        $author = $this->rolesStorage->getRoleByName('author');

        $this->manager->removeChildren($author);
        $this->assertFalse($this->rolesStorage->hasChildren('author'));
    }

    public function testHasChild(): void
    {
        $author = $this->rolesStorage->getRoleByName('author');
        $reader = $this->rolesStorage->getRoleByName('reader');
        $permission = $this->rolesStorage->getPermissionByName('createPost');

        $this->assertTrue($this->manager->hasChild($author, $permission));
        $this->assertFalse($this->manager->hasChild($reader, $permission));
    }

    public function testAssign(): void
    {
        $this->manager->assign(
            $this->rolesStorage->getRoleByName('reader'),
            'readingAuthor'
        );
        $this->manager->assign(
            $this->rolesStorage->getRoleByName('author'),
            'readingAuthor'
        );

        $this->assertEquals(
            [
                'myDefaultRole',
                'reader',
                'author',
            ],
            array_keys($this->manager->getRolesByUser('readingAuthor'))
        );
    }

    public function testAssignUnknownItem(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unknown role "nonExistRole".');

        $this->manager->assign(
            new Role('nonExistRole'),
            'reader'
        );
    }

    public function testAssignAlreadyAssignedItem(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('"reader" role has already been assigned to user reader A.');

        $this->manager->assign(
            $this->rolesStorage->getRoleByName('reader'),
            'reader A'
        );
    }

    public function testAssignPermissionDirectlyWhenItIsDisabled(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Assigning permissions directly is disabled. Prefer assigning roles only.');

        $this->manager->assign(
            $this->rolesStorage->getPermissionByName('updateAnyPost'),
            'reader'
        );
    }

    public function testAssignPermissionDirectlyWhenItIsEnabled(): void
    {
        $this->manager = $this->createManager($this->rolesStorage, $this->assignmentsStorage, true);

        $this->manager->assign(
            $this->rolesStorage->getPermissionByName('updateAnyPost'),
            'reader'
        );

        $this->assertTrue($this->manager->userHasPermission('reader', 'updateAnyPost'));
    }

    public function testGetRolesByUser(): void
    {
        $this->assertEquals(
            ['myDefaultRole', 'reader'],
            array_keys($this->manager->getRolesByUser('reader A'))
        );
    }

    public function testGetChildRoles(): void
    {
        $this->assertEquals(
            ['admin', 'reader', 'author'],
            array_keys($this->manager->getChildRoles('admin'))
        );
    }

    public function testGetChildRolesUnknownRole(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Role "unknown" not found.');

        $this->manager->getChildRoles('unknown');
    }

    public function testGetPermissionsByRole(): void
    {
        $this->assertEquals(
            ['createPost', 'updatePost', 'readPost', 'updateAnyPost'],
            array_keys($this->manager->getPermissionsByRole('admin'))
        );

        $this->assertEmpty($this->manager->getPermissionsByRole('guest'));
    }

    public function testGetPermissionsByUser(): void
    {
        $this->assertEquals(
            ['deletePost', 'createPost', 'updatePost', 'readPost'],
            array_keys($this->manager->getPermissionsByUser('author B'))
        );
    }

    public function testUserIdsByRole(): void
    {
        $this->assertEquals(
            [
                'reader A',
                'author B',
                'admin C',
            ],
            $this->manager->getUserIdsByRole('reader')
        );
        $this->assertEquals(
            [
                'author B',
                'admin C',
            ],
            $this->manager->getUserIdsByRole('author')
        );
        $this->assertEquals(['admin C'], $this->manager->getUserIdsByRole('admin'));
    }

    public function testAddRole(): void
    {
        $rule = new EasyRule();

        $role = (new Role('new role'))
            ->withDescription('new role description')
            ->withRuleName($rule->getName());

        $this->manager->addRole($role);
        $this->assertNotNull($this->rolesStorage->getRoleByName('new role'));
    }

    public function testRemoveRole(): void
    {
        $this->manager->removeRole($this->rolesStorage->getRoleByName('reader'));
        $this->assertNull($this->rolesStorage->getRoleByName('new role'));
    }

    public function testUpdateRoleNameAndRule(): void
    {
        $role = $this->rolesStorage->getRoleByName('reader')->withName('new reader');
        $this->manager->updateRole('reader', $role);

        $this->assertNull($this->rolesStorage->getRoleByName('reader'));
        $this->assertNotNull($this->rolesStorage->getRoleByName('new reader'));
    }

    public function testAddPermission(): void
    {
        $permission = (new Permission('edit post'))
            ->withDescription('edit a post');

        $this->manager->addPermission($permission);
        $this->assertNotNull($this->rolesStorage->getPermissionByName('edit post'));
    }

    public function testRemovePermission(): void
    {
        $this->manager->removePermission($this->rolesStorage->getPermissionByName('updatePost'));
        $this->assertNull($this->rolesStorage->getPermissionByName('updatePost'));
    }

    public function testUpdatePermission(): void
    {
        $permission = $this->rolesStorage->getPermissionByName('updatePost')
            ->withName('newUpdatePost');

        $this->manager->updatePermission('updatePost', $permission);

        $this->assertNull($this->rolesStorage->getPermissionByName('updatePost'));
        $this->assertNotNull($this->rolesStorage->getPermissionByName('newUpdatePost'));
    }

    public function testUpdatePermissionNameAlreadyUsed(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Unable to change the item name. The name "createPost" is already used by another item.'
        );

        $permission = $this->rolesStorage->getPermissionByName('updatePost')
            ->withName('createPost');

        $this->manager->updatePermission('updatePost', $permission);
    }

    public function testAddRule(): void
    {
        $ruleName = 'isReallyReallyAuthor';
        $rule = new AuthorRule($ruleName, true);

        $this->manager->addRule($rule);

        $rule = $this->rolesStorage->getRuleByName($ruleName);
        $this->assertEquals($ruleName, $rule->getName());
        $this->assertTrue($rule->isReallyReally());
    }

    public function testRemoveRule(): void
    {
        $this->manager->removeRule(
            $this->rolesStorage->getRuleByName('isAuthor')
        );

        $this->assertNull($this->rolesStorage->getRuleByName('isAuthor'));
    }

    public function testUpdateRule(): void
    {
        $rule = $this->rolesStorage->getRuleByName('isAuthor')
            ->withName('newName')
            ->withReallyReally(false);

        $this->manager->updateRule('isAuthor', $rule);
        $this->assertNull($this->rolesStorage->getRuleByName('isAuthor'));
        $this->assertNotNull($this->rolesStorage->getRuleByName('newName'));
    }

    public function testDefaultRolesSetWithClosure(): void
    {
        $this->manager->setDefaultRoles(
            static function () {
                return ['newDefaultRole'];
            }
        );

        $this->assertEquals(['newDefaultRole'], $this->manager->getDefaultRoles());
    }

    public function testDefaultRolesWithClosureReturningNonArrayValue(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Default roles closure must return an array');

        $this->manager->setDefaultRoles(
            static function () {
                return 'test';
            }
        );
    }

    public function testDefaultRolesWithNonArrayValue(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Default roles must be either an array or a closure');

        $this->manager->setDefaultRoles('test');
    }

    public function testGetDefaultRoles(): void
    {
        $this->assertEquals(['myDefaultRole'], $this->manager->getDefaultRoles());
    }

    protected function createManager(
        RolesStorageInterface $rolesStorage,
        AssignmentsStorageInterface $assignmentsStorage,
        bool $enableDirectPermissions = false
    ): Manager
    {
        return (new Manager($rolesStorage, $assignmentsStorage, new ClassNameRuleFactory(), $enableDirectPermissions))
            ->setDefaultRoles(['myDefaultRole']);
    }

    protected function createRolesStorage(): RolesStorageInterface
    {
        $storage = new FakeRolesStorage();

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

    protected function createAssignmentsStorage(): AssignmentsStorageInterface
    {
        $storage = new FakeAssignmentsStorage();

        $storage->addAssignment('reader A', new Permission('Fast Metabolism'));
        $storage->addAssignment('reader A', new Role('reader'));
        $storage->addAssignment('author B', new Role('author'));
        $storage->addAssignment('author B', new Permission('deletePost'));
        $storage->addAssignment('admin C', new Role('admin'));

        return $storage;
    }

    public function testRevokeRole(): void
    {
        $this->manager->revoke(
            $this->rolesStorage->getRoleByName('reader'),
            'reader A'
        );

        $this->assertEquals(['Fast Metabolism'], array_keys($this->assignmentsStorage->getUserAssignments('reader A')));
    }

    public function testRevokePermission(): void
    {
        $this->manager->revoke(
            $this->rolesStorage->getPermissionByName('deletePost'),
            'author B'
        );

        $this->assertEquals(['author'], array_keys($this->assignmentsStorage->getUserAssignments('author B')));
    }

    public function testRevokeAll(): void
    {
        $this->manager->revokeAll('author B');
        $this->assertEmpty($this->assignmentsStorage->getUserAssignments('author B'));
    }
}
