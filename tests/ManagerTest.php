<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Yiisoft\Rbac\AssignmentsStorageInterface;
use Yiisoft\Rbac\Exception\RuleNotFoundException;
use Yiisoft\Rbac\Manager;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\Role;
use Yiisoft\Rbac\ItemsStorageInterface;
use Yiisoft\Rbac\Tests\Support\AuthorRule;
use Yiisoft\Rbac\Tests\Support\EasyRule;
use Yiisoft\Rbac\Tests\Support\FakeAssignmentsStorage;
use Yiisoft\Rbac\Tests\Support\FakeItemsStorage;
use Yiisoft\Rbac\Tests\Support\SimpleRuleFactory;

/**
 * @group rbac
 */
final class ManagerTest extends TestCase
{
    private const NOW = 1642027031;

    private ItemsStorageInterface $itemsStorage;

    private AssignmentsStorageInterface $assignmentsStorage;

    protected function setUp(): void
    {
        parent::setUp();
        $this->itemsStorage = $this->createItemsStorage();
        $this->assignmentsStorage = $this->createAssignmentsStorage();
    }

    /**
     * @dataProvider dataProviderUserHasPermission
     */
    public function testUserHasPermission($user, array $tests): void
    {
        $manager = $this->createManager();

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
            [
                null,
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
     * @dataProvider dataProviderUserHasPermissionWithGuest
     */
    public function testUserHasPermissionWithGuest($userId, array $tests): void
    {
        $manager = $this->createManager();

        $manager->setGuestRoleName('guest');
        $this->itemsStorage->add(new Role('guest'));
        $this->itemsStorage->add(new Permission('signup'));
        $this->itemsStorage->addChild('guest', 'signup');

        foreach ($tests as $permission => $result) {
            $this->assertEquals(
                $result,
                $manager->userHasPermission($userId, $permission),
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
        $manager = $this->createManager();

        $manager->setGuestRoleName('non-exist-guest');

        $this->assertFalse(
            $manager->userHasPermission(null, 'readPost')
        );
    }

    /**
     * @dataProvider dataProviderUserHasPermissionWithFailUserId
     */
    public function testUserHasPermissionWithFailUserId($userId): void
    {
        $manager = $this->createManager();

        $this->expectException(InvalidArgumentException::class);

        $permission = 'createPost';
        $params = ['authorID' => 'author B'];

        $manager->userHasPermission($userId, $permission, $params);
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
        $manager = $this->createManager();

        $manager->setDefaultRoleNames([]);
        $this->assertFalse($manager->userHasPermission('unknown user', 'createPost'));
    }

    public function testUserHasPermissionWithNonExistsRule(): void
    {
        $manager = $this->createManager();

        $permission = (new Permission('test-permission'))->withRuleName('non-exist-rule');
        $role = (new Role('test'));
        $this->itemsStorage->add($role);
        $this->itemsStorage->add($permission);
        $this->itemsStorage->addChild('test', 'test-permission');

        $this->expectException(RuleNotFoundException::class);
        $this->expectErrorMessage('Rule "non-exist-rule" not found.');
        $manager->userHasPermission('reader A', 'test-permission');
    }

    public function testCanAddChildReturnTrue(): void
    {
        $manager = $this->createManager();

        $this->assertTrue(
            $manager->canAddChild(
                'author',
                'reader'
            )
        );
    }

    public function testCanAddChildDetectsLoops(): void
    {
        $manager = $this->createManager();

        $this->assertFalse(
            $manager->canAddChild(
                'reader',
                'author'
            )
        );
    }

    public function testCanAddChildPermissionToRole(): void
    {
        $manager = $this->createManager();

        $this->assertFalse(
            $manager->canAddChild(
                'readPost',
                'reader'
            )
        );
    }

    public function testCanAddChildToNonExistItem(): void
    {
        $itemsStorage = new FakeItemsStorage();
        $itemsStorage->add(new Role('author'));

        $manager = new Manager(
            $itemsStorage,
            new FakeAssignmentsStorage(),
            new SimpleRuleFactory(),
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('There is no item named "admin".');
        $manager->canAddChild('admin', 'author');
    }

    public function testCanAddNonExistChild(): void
    {
        $itemsStorage = new FakeItemsStorage();
        $itemsStorage->add(new Role('author'));

        $manager = new Manager(
            $itemsStorage,
            new FakeAssignmentsStorage(),
            new SimpleRuleFactory(),
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('There is no item named "reader".');
        $manager->canAddChild('author', 'reader');
    }

    public function testAddChild(): void
    {
        $manager = $this->createManager();

        $manager->addChild(
            'reader',
            'createPost'
        );

        $this->assertEquals(
            [
                'readPost',
                'createPost',
            ],
            array_keys($this->itemsStorage->getChildren('reader'))
        );
    }

    public function testAddChildNotHasItem(): void
    {
        $manager = $this->createManager();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Either "new reader" does not exist.');

        $manager->addChild(
            'new reader',
            'createPost'
        );
    }

    public function testAddChildEqualName(): void
    {
        $manager = $this->createManager();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot add "createPost" as a child of itself.');

        $manager->addChild(
            'createPost',
            'createPost'
        );
    }

    public function testAddChildPermissionToRole(): void
    {
        $manager = $this->createManager();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Can not add "reader" role as a child of "createPost" permission.');

        $manager->addChild(
            'createPost',
            'reader'
        );
    }

    public function testAddChildAlreadyAdded(): void
    {
        $manager = $this->createManager();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The item "reader" already has a child "readPost".');

        $manager->addChild(
            'reader',
            'readPost'
        );
    }

    public function testAddChildDetectLoop(): void
    {
        $manager = $this->createManager();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Cannot add "author" as a child of "reader". A loop has been detected.');

        $manager->addChild(
            'reader',
            'author',
        );
    }

    public function testAddChildWithNonExistChild(): void
    {
        $manager = $this->createManager();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Either "new reader" does not exist.');
        $manager->addChild('reader', 'new reader');
    }

    public function testRemoveChild(): void
    {
        $manager = $this->createManager();

        $manager->removeChild(
            'author',
            'createPost',
        );

        $this->assertEquals(
            [
                'updatePost',
                'reader',
            ],
            array_keys($this->itemsStorage->getChildren('author'))
        );
    }

    public function testRemoveChildren(): void
    {
        $manager = $this->createManager();

        $manager->removeChildren('author');
        $this->assertFalse($this->itemsStorage->hasChildren('author'));
    }

    public function testHasChild(): void
    {
        $manager = $this->createManager();

        $this->assertTrue($manager->hasChild('author', 'createPost'));
        $this->assertFalse($manager->hasChild('reader', 'createPost'));
    }

    public function testAssign(): void
    {
        $manager = $this->createManager();

        $readerAssignment = $manager->assign(
            'reader',
            'readingAuthor'
        );
        $authorAssignment = $manager->assign(
            'author',
            'readingAuthor'
        );

        $this->assertEquals(
            [
                'myDefaultRole',
                'reader',
                'author',
            ],
            array_keys($manager->getRolesByUserId('readingAuthor'))
        );

        $this->assertSame('readingAuthor', $readerAssignment->getUserId());
        $this->assertSame('reader', $readerAssignment->getItemName());
        $this->assertSame(self::NOW, $readerAssignment->getCreatedAt());

        $this->assertSame('readingAuthor', $authorAssignment->getUserId());
        $this->assertSame('author', $authorAssignment->getItemName());
        $this->assertSame(self::NOW, $authorAssignment->getCreatedAt());
    }

    public function testAssignUnknownItem(): void
    {
        $manager = $this->createManager();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('There is no item named "nonExistRole".');

        $manager->assign(
            'nonExistRole',
            'reader'
        );
    }

    public function testAssignAlreadyAssignedItem(): void
    {
        $manager = $this->createManager();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('"reader" role has already been assigned to user reader A.');

        $manager->assign(
            'reader',
            'reader A'
        );
    }

    public function testAssignPermissionDirectlyWhenItIsDisabled(): void
    {
        $manager = $this->createManager();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Assigning permissions directly is disabled. Prefer assigning roles only.');

        $manager->assign(
            'updateAnyPost',
            'reader'
        );
    }

    public function testAssignPermissionDirectlyWhenItIsEnabled(): void
    {
        $manager = $this->createManager(true);

        $manager->assign(
            'updateAnyPost',
            'reader'
        );

        $this->assertTrue($manager->userHasPermission('reader', 'updateAnyPost'));
    }

    public function testGetRolesByUser(): void
    {
        $manager = $this->createManager();

        $this->assertEquals(
            ['myDefaultRole', 'reader'],
            array_keys($manager->getRolesByUserId('reader A'))
        );
    }

    public function testGetChildRoles(): void
    {
        $manager = $this->createManager();

        $this->assertEquals(
            ['admin', 'reader', 'author'],
            array_keys($manager->getChildRoles('admin'))
        );
    }

    public function testGetChildRolesUnknownRole(): void
    {
        $manager = $this->createManager();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Role "unknown" not found.');

        $manager->getChildRoles('unknown');
    }

    public function testGetPermissionsByRole(): void
    {
        $manager = $this->createManager();

        $this->assertEquals(
            ['createPost', 'updatePost', 'readPost', 'updateAnyPost'],
            array_keys($manager->getPermissionsByRoleName('admin'))
        );

        $this->assertEmpty($manager->getPermissionsByRoleName('guest'));
    }

    public function testGetPermissionsByUser(): void
    {
        $manager = $this->createManager();

        $this->assertSame(
            ['deletePost', 'createPost', 'updatePost', 'readPost'],
            array_keys($manager->getPermissionsByUserId('author B'))
        );
    }

    public function testGetPermissionsByUserForUserWithoutPermissions(): void
    {
        $manager = $this->createManager();

        $this->assertSame(
            [],
            array_keys($manager->getPermissionsByUserId('guest'))
        );
    }

    public function testUserIdsByRole(): void
    {
        $manager = $this->createManager();

        $this->assertEquals(
            [
                'reader A',
                'author B',
                'admin C',
            ],
            $manager->getUserIdsByRoleName('reader')
        );
        $this->assertEquals(
            [
                'author B',
                'admin C',
            ],
            $manager->getUserIdsByRoleName('author')
        );
        $this->assertEquals(['admin C'], $manager->getUserIdsByRoleName('admin'));
    }

    public function testAddRole(): void
    {
        $manager = $this->createManager();

        $rule = new EasyRule();

        $role = (new Role('new role'))
            ->withDescription('new role description')
            ->withRuleName($rule->getName())
            ->withCreatedAt(1642026147)
            ->withUpdatedAt(1642026148);

        $manager->addRole($role);

        $storedRole = $this->itemsStorage->getRole('new role');

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
        $manager = $this->createManager();

        $manager->removeRole('reader');
        $this->assertNull($this->itemsStorage->getRole('new role'));
    }

    public function testUpdateRoleNameAndRule(): void
    {
        $manager = $this->createManager();

        $role = $this->itemsStorage->getRole('reader')->withName('new reader');
        $manager->updateRole('reader', $role);

        $this->assertNull($this->itemsStorage->getRole('reader'));
        $this->assertNotNull($this->itemsStorage->getRole('new reader'));
    }

    public function testAddPermission(): void
    {
        $manager = $this->createManager();

        $permission = (new Permission('edit post'))
            ->withDescription('edit a post')
            ->withCreatedAt(1642026147)
            ->withUpdatedAt(1642026148);

        $manager->addPermission($permission);

        $storedPermission = $this->itemsStorage->getPermission('edit post');

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
        $manager = $this->createManager();

        $permission = new Permission('test');
        $manager->addPermission($permission);

        $storedPermission = $this->itemsStorage->getPermission('test');

        $this->assertNotNull($storedPermission);
        $this->assertNotNull($storedPermission->getCreatedAt());
        $this->assertNotNull($storedPermission->getUpdatedAt());
    }

    public function testRemovePermission(): void
    {
        $manager = $this->createManager();

        $manager->removePermission('updatePost');
        $this->assertNull($this->itemsStorage->getPermission('updatePost'));
    }

    public function testUpdatePermission(): void
    {
        $manager = $this->createManager();

        $permission = $this->itemsStorage->getPermission('updatePost')
            ->withName('newUpdatePost')
            ->withCreatedAt(1642026149)
            ->withUpdatedAt(1642026150);

        $manager->updatePermission('updatePost', $permission);

        $this->assertNull($this->itemsStorage->getPermission('updatePost'));
        $newPermission = $this->itemsStorage->getPermission('newUpdatePost');
        $this->assertNotNull($newPermission);
        $this->assertSame(1642026149, $newPermission->getCreatedAt());
        $this->assertSame(1642026150, $newPermission->getUpdatedAt());
    }

    public function testUpdatePermissionNameAlreadyUsed(): void
    {
        $manager = $this->createManager();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Unable to change the role or the permission name. ' .
            'The name "createPost" is already used by another role or permission.'
        );

        $permission = $this->itemsStorage->getPermission('updatePost')
            ->withName('createPost');

        $manager->updatePermission('updatePost', $permission);
    }

    public function testDefaultRolesSetWithClosure(): void
    {
        $manager = $this->createManager();

        $manager->setDefaultRoleNames(
            static function () {
                return ['newDefaultRole'];
            }
        );

        $this->assertEquals(['newDefaultRole'], $manager->getDefaultRoleNames());
    }

    public function testDefaultRolesWithClosureReturningNonArrayValue(): void
    {
        $manager = $this->createManager();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Default role names closure must return an array');

        $manager->setDefaultRoleNames(
            static function () {
                return 'test';
            }
        );
    }

    public function testDefaultRolesWithNonArrayValue(): void
    {
        $manager = $this->createManager();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Default role names must be either an array or a closure');

        $manager->setDefaultRoleNames('test');
    }

    public function testGetDefaultRoles(): void
    {
        $manager = $this->createManager();

        $this->assertEquals(['myDefaultRole'], $manager->getDefaultRoleNames());
    }

    public function testGetDefaultNonExistRoles(): void
    {
        $manager = new Manager(
            new FakeItemsStorage(),
            new FakeAssignmentsStorage(),
            new SimpleRuleFactory(),
        );

        $manager->setDefaultRoleNames(['bananaCollector']);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Default role "bananaCollector" not found.');
        $manager->getDefaultRoles();
    }

    private function createManager(bool $enableDirectPermissions = false): Manager
    {
        $manager = new Manager(
            $this->itemsStorage,
            $this->assignmentsStorage,
            new SimpleRuleFactory([
                'isAuthor' => new AuthorRule(),
            ]),
            $enableDirectPermissions
        );

        $manager->setDefaultRoleNames(['myDefaultRole']);

        return $manager;
    }

    private function createItemsStorage(): ItemsStorageInterface
    {
        $storage = new FakeItemsStorage();

        $storage->add(new Permission('Fast Metabolism'));
        $storage->add(new Permission('createPost'));
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

    private function createAssignmentsStorage(): AssignmentsStorageInterface
    {
        $storage = new FakeAssignmentsStorage(self::NOW);

        $storage->add('Fast Metabolism', 'reader A');
        $storage->add('reader', 'reader A');
        $storage->add('author', 'author B');
        $storage->add('deletePost', 'author B');
        $storage->add('admin', 'admin C');

        return $storage;
    }

    public function testRevokeRole(): void
    {
        $manager = $this->createManager();

        $manager->revoke(
            'reader',
            'reader A'
        );

        $this->assertEquals(['Fast Metabolism'], array_keys($this->assignmentsStorage->getByUserId('reader A')));
    }

    public function testRevokePermission(): void
    {
        $manager = $this->createManager();

        $manager->revoke(
            'deletePost',
            'author B'
        );

        $this->assertEquals(['author'], array_keys($this->assignmentsStorage->getByUserId('author B')));
    }

    public function testRevokeAll(): void
    {
        $manager = $this->createManager();

        $manager->revokeAll('author B');
        $this->assertEmpty($this->assignmentsStorage->getByUserId('author B'));
    }
}
