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
use Yiisoft\Rbac\ClassNameRuleFactory;
use Yiisoft\Rbac\Tests\Support\AuthorRule;
use Yiisoft\Rbac\Tests\Support\EasyRule;
use Yiisoft\Rbac\Tests\Support\FakeAssignmentsStorage;
use Yiisoft\Rbac\Tests\Support\FakeRolesStorage;

/**
 * @group rbac
 */
final class ManagerTest extends TestCase
{
    private const NOW = 1642027031;

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

    public function dataUserHasPermission(): array
    {
        return [
            // reader A
            [false, 'reader A', 'createPost'],
            [true, 'reader A', 'readPost'],
            [false, 'reader A', 'updatePost', ['authorID' => 'author B']],
            [false, 'reader A', 'updateAnyPost'],
            [false, 'reader A', 'reader'],
            [false, 'reader A', 'withoutChildren'],
            [false, 'reader A', 'nonExistingPermission'],

            // author B
            [true, 'author B', 'createPost'],
            [true, 'author B', 'readPost'],
            [true, 'author B', 'updatePost', ['authorID' => 'author B']],
            [false, 'author B', 'updateAnyPost'],

            // admin C
            [true, 'admin C', 'createPost'],
            [true, 'admin C', 'readPost'],
            [false, 'admin C', 'updatePost', ['authorID' => 'author B']],
            [true, 'admin C', 'updateAnyPost'],

            // non-exist-user
            [false, 'non-exist-user', 'createPost'],
            [false, 'non-exist-user', 'readPost'],
            [false, 'non-exist-user', 'updatePost', ['authorID' => 'author B']],
            [false, 'non-exist-user', 'updateAnyPost'],
            [false, 'non-exist-user', 'reader'],
            [false, 'non-exist-user', 'withoutChildren'],
            [false, 'non-exist-user', 'nonExistingPermission'],

            // guest
            [false, null, 'createPost'],
            [false, null, 'readPost'],
            [false, null, 'updatePost', ['authorID' => 'author B']],
            [false, null, 'updateAnyPost'],
            [false, null, 'reader'],
            [false, null, 'withoutChildren'],
            [false, null, 'nonExistingPermission'],
        ];
    }

    /**
     * @dataProvider dataUserHasPermission
     */
    public function testUserHasPermission(bool $expected, $user, string $permissionName, array $parameters = []): void
    {
        $this->assertSame(
            $expected,
            $this->manager->userHasPermission($user, $permissionName, $parameters),
        );
    }

    /**
     * @dataProvider dataProviderUserHasPermissionWithGuest
     */
    public function testUserHasPermissionWithGuest($userId, array $tests): void
    {
        $this->manager->setGuestRoleName('guest');
        $this->rolesStorage->addItem(new Role('guest'));
        $this->rolesStorage->addItem(new Permission('signup'));
        $this->rolesStorage->addChild(new Role('guest'), new Permission('signup'));

        foreach ($tests as $permission => $result) {
            $this->assertEquals(
                $result,
                $this->manager->userHasPermission($userId, $permission),
                sprintf('Checking "%s" can "%s"', $userId, $permission)
            );
        }
    }

    public function dataProviderUserHasPermissionWithGuest(): array
    {
        return [
            [
                null,
                [
                    'createPost' => false,
                    'readPost' => false,
                    'updatePost' => false,
                    'deletePost' => false,
                    'updateAnyPost' => false,
                    'signup' => true,
                    null => false,
                ],
            ],
        ];
    }

    public function testUserHasPermissionWithNonExistGuestRole(): void
    {
        $this->manager->setGuestRoleName('non-exist-guest');

        $this->assertFalse(
            $this->manager->userHasPermission(null, 'readPost')
        );
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
            [(object) []],
            [['test' => 1]],
        ];
    }

    public function testUserHasPermissionReturnFalseForNonExistingUserAndNoDefaultRoles(): void
    {
        $this->manager->setDefaultRoleNames([]);
        $this->assertFalse($this->manager->userHasPermission('unknown user', 'createPost'));
    }

    public function testUserHasPermissionWithNonExistsRule(): void
    {
        $permission = (new Permission('test-permission'))->withRuleName('non-exist-rule');
        $role = (new Role('test'));
        $this->rolesStorage->addItem($role);
        $this->rolesStorage->addItem($permission);
        $this->rolesStorage->addChild($role, $permission);

        $this->expectException(RuntimeException::class);
        $this->expectErrorMessage('Rule "non-exist-rule" not found.');
        $this->manager->userHasPermission('reader A', 'test-permission');
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

    public function testAddChildWithNonExistChild(): void
    {
        $parent = $this->rolesStorage->getRoleByName('reader');
        $child = new Role('new reader');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Either "new reader" does not exist.');
        $this->manager->addChild($parent, $child);
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
        $readerAssignment = $this->manager->assign(
            $this->rolesStorage->getRoleByName('reader'),
            'readingAuthor'
        );
        $authorAssignment = $this->manager->assign(
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

        $this->assertSame('readingAuthor', $readerAssignment->getUserId());
        $this->assertSame('reader', $readerAssignment->getRoleName());
        $this->assertSame(self::NOW, $readerAssignment->getCreatedAt());

        $this->assertSame('readingAuthor', $authorAssignment->getUserId());
        $this->assertSame('author', $authorAssignment->getRoleName());
        $this->assertSame(self::NOW, $authorAssignment->getCreatedAt());
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
        $roleNames = array_keys($this->manager->getRolesByUser('reader A'));

        $this->assertSame(
            ['myDefaultRole', 'reader', 'observer'],
            $roleNames
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
        $permissionNames = array_keys($this->manager->getPermissionsByUser('author B'));

        $this->assertSame(
            ['createPost', 'updatePost', 'readPost'],
            $permissionNames
        );
    }

    public function testGetPermissionsByUserForUserWithoutPermissions(): void
    {
        $this->assertSame(
            [],
            array_keys($this->manager->getPermissionsByUser('guest'))
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
            ->withRuleName($rule->getName())
            ->withCreatedAt(1642026147)
            ->withUpdatedAt(1642026148);

        $this->manager->addRole($role);

        $storedRole = $this->rolesStorage->getRoleByName('new role');

        $this->assertNotNull($storedRole);
        $this->assertSame('new role description', $storedRole->getDescription());
        $this->assertSame(1642026147, $storedRole->getCreatedAt());
        $this->assertSame(1642026148, $storedRole->getUpdatedAt());
        $this->assertSame(
            [
                'name' => 'new role',
                'description' => 'new role description',
                'ruleName' => EasyRule::class,
                'type' => 'role',
                'updatedAt' => 1642026148,
                'createdAt' => 1642026147,
            ],
            $storedRole->getAttributes()
        );
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
            ->withDescription('edit a post')
            ->withCreatedAt(1642026147)
            ->withUpdatedAt(1642026148);

        $this->manager->addPermission($permission);

        $storedPermission = $this->rolesStorage->getPermissionByName('edit post');

        $this->assertNotNull($storedPermission);
        $this->assertSame('edit a post', $storedPermission->getDescription());
        $this->assertSame(1642026147, $storedPermission->getCreatedAt());
        $this->assertSame(1642026148, $storedPermission->getUpdatedAt());
        $this->assertSame(
            [
                'name' => 'edit post',
                'description' => 'edit a post',
                'ruleName' => null,
                'type' => 'permission',
                'updatedAt' => 1642026148,
                'createdAt' => 1642026147,
            ],
            $storedPermission->getAttributes()
        );
    }

    public function testAddPermissionWithoutTime(): void
    {
        $permission = new Permission('test');
        $this->manager->addPermission($permission);

        $storedPermission = $this->rolesStorage->getPermissionByName('test');

        $this->assertNotNull($storedPermission);
        $this->assertNotNull($storedPermission->getCreatedAt());
        $this->assertNotNull($storedPermission->getUpdatedAt());
    }

    public function testRemovePermission(): void
    {
        $this->manager->removePermission($this->rolesStorage->getPermissionByName('updatePost'));
        $this->assertNull($this->rolesStorage->getPermissionByName('updatePost'));
    }

    public function testUpdatePermission(): void
    {
        $permission = $this->rolesStorage->getPermissionByName('updatePost')
            ->withName('newUpdatePost')
            ->withCreatedAt(1642026149)
            ->withUpdatedAt(1642026150);

        $this->manager->updatePermission('updatePost', $permission);

        $this->assertNull($this->rolesStorage->getPermissionByName('updatePost'));
        $newPermission = $this->rolesStorage->getPermissionByName('newUpdatePost');
        $this->assertNotNull($newPermission);
        $this->assertSame(1642026149, $newPermission->getCreatedAt());
        $this->assertSame(1642026150, $newPermission->getUpdatedAt());
    }

    public function testUpdatePermissionNameAlreadyUsed(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Unable to change the role or the permission name. ' .
            'The name "createPost" is already used by another role or permission.'
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
        $this->manager->setDefaultRoleNames(
            static function () {
                return ['newDefaultRole'];
            }
        );

        $this->assertEquals(['newDefaultRole'], $this->manager->getDefaultRoleNames());
    }

    public function testDefaultRolesWithClosureReturningNonArrayValue(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Default role names closure must return an array');

        $this->manager->setDefaultRoleNames(
            static function () {
                return 'test';
            }
        );
    }

    public function testDefaultRolesWithNonArrayValue(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Default role names must be either an array or a closure');

        $this->manager->setDefaultRoleNames('test');
    }

    public function testGetDefaultRoles(): void
    {
        $this->assertEquals(['myDefaultRole'], $this->manager->getDefaultRoleNames());
    }

    private function createManager(
        RolesStorageInterface $rolesStorage,
        AssignmentsStorageInterface $assignmentsStorage,
        bool $enableDirectPermissions = false
    ): Manager {
        return (new Manager($rolesStorage, $assignmentsStorage, new ClassNameRuleFactory(), $enableDirectPermissions))
            ->setDefaultRoleNames(['myDefaultRole']);
    }

    private function createRolesStorage(): RolesStorageInterface
    {
        $storage = new FakeRolesStorage();

        $storage->addItem(new Permission('createPost'));
        $storage->addItem(new Permission('readPost'));
        $storage->addItem((new Permission('updatePost'))->withRuleName('isAuthor'));
        $storage->addItem(new Permission('updateAnyPost'));
        $storage->addItem(new Role('withoutChildren'));
        $storage->addItem(new Role('reader'));
        $storage->addItem(new Role('author'));
        $storage->addItem(new Role('admin'));
        $storage->addItem(new Role('observer'));

        $storage->addChild(new Role('reader'), new Permission('readPost'));
        $storage->addChild(new Role('author'), new Permission('createPost'));
        $storage->addChild(new Role('author'), new Permission('updatePost'));
        $storage->addChild(new Role('author'), new Role('reader'));
        $storage->addChild(new Role('admin'), new Role('author'));
        $storage->addChild(new Role('admin'), new Permission('updateAnyPost'));

        $storage->addRule(new AuthorRule('isAuthor'));

        return $storage;
    }

    private function createAssignmentsStorage(): AssignmentsStorageInterface
    {
        $storage = new FakeAssignmentsStorage(self::NOW);

        $storage->addAssignment('reader A', new Role('reader'));
        $storage->addAssignment('reader A', new Role('observer'));
        $storage->addAssignment('author B', new Role('author'));
        $storage->addAssignment('admin C', new Role('admin'));

        return $storage;
    }

    public function testRevokeRole(): void
    {
        $this->manager->revoke(
            $this->rolesStorage->getRoleByName('reader'),
            'reader A'
        );

        $this->assertSame(['observer'], array_keys($this->assignmentsStorage->getUserAssignments('reader A')));
    }

    public function testRevokeAll(): void
    {
        $this->manager->revokeAll('author B');
        $this->assertEmpty($this->assignmentsStorage->getUserAssignments('author B'));
    }
}
