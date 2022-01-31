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
use Yiisoft\Rbac\ItemsStorageInterface;
use Yiisoft\Rbac\ClassNameRuleFactory;
use Yiisoft\Rbac\Tests\Support\AuthorRule;
use Yiisoft\Rbac\Tests\Support\EasyRule;
use Yiisoft\Rbac\Tests\Support\FakeAssignmentsStorage;
use Yiisoft\Rbac\Tests\Support\FakeItemsStorage;

/**
 * @group rbac
 */
final class ManagerTest extends TestCase
{
    private const NOW = 1642027031;

    private Manager $manager;

    private ItemsStorageInterface $itemsStorage;

    private AssignmentsStorageInterface $assignmentsStorage;

    protected function setUp(): void
    {
        parent::setUp();
        $this->itemsStorage = $this->createItemsStorage();
        $this->assignmentsStorage = $this->createAssignmentsStorage();
        $this->manager = $this->createManager($this->itemsStorage, $this->assignmentsStorage);
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
        $this->manager->setGuestRoleName('guest');
        $this->itemsStorage->add(new Role('guest'));
        $this->itemsStorage->add(new Permission('signup'));
        $this->itemsStorage->addChild('guest', 'signup');

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
        $this->itemsStorage->add($role);
        $this->itemsStorage->add($permission);
        $this->itemsStorage->addChild('test', 'test-permission');

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
            $this->itemsStorage->getRole('reader'),
            $this->itemsStorage->getPermission('createPost')
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
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Either "new reader" does not exist.');

        $this->manager->addChild(
            new Role('new reader'),
            $this->itemsStorage->getPermission('createPost')
        );
    }

    public function testAddChildEqualName(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot add "createPost" as a child of itself.');

        $this->manager->addChild(
            new Role('createPost'),
            $this->itemsStorage->getPermission('createPost')
        );
    }

    public function testAddChildPermissionToRole(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Can not add "reader" role as a child of "createPost" permission.');

        $this->manager->addChild(
            $this->itemsStorage->getPermission('createPost'),
            $this->itemsStorage->getRole('reader')
        );
    }

    public function testAddChildAlreadyAdded(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The item "reader" already has a child "readPost".');

        $this->manager->addChild(
            $this->itemsStorage->getRole('reader'),
            $this->itemsStorage->getPermission('readPost')
        );
    }

    public function testAddChildDetectLoop(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Cannot add "author" as a child of "reader". A loop has been detected.');

        $this->manager->addChild(
            $this->itemsStorage->getRole('reader'),
            $this->itemsStorage->getRole('author'),
        );
    }

    public function testAddChildWithNonExistChild(): void
    {
        $parent = $this->itemsStorage->getRole('reader');
        $child = new Role('new reader');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Either "new reader" does not exist.');
        $this->manager->addChild($parent, $child);
    }

    public function testRemoveChild(): void
    {
        $this->manager->removeChild(
            $this->itemsStorage->getRole('author'),
            $this->itemsStorage->getPermission('createPost'),
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
        $this->manager->removeChildren('author');
        $this->assertFalse($this->itemsStorage->hasChildren('author'));
    }

    public function testHasChild(): void
    {
        $author = $this->itemsStorage->getRole('author');
        $reader = $this->itemsStorage->getRole('reader');
        $permission = $this->itemsStorage->getPermission('createPost');

        $this->assertTrue($this->manager->hasChild($author, $permission));
        $this->assertFalse($this->manager->hasChild($reader, $permission));
    }

    public function testAssign(): void
    {
        $readerAssignment = $this->manager->assign(
            $this->itemsStorage->getRole('reader'),
            'readingAuthor'
        );
        $authorAssignment = $this->manager->assign(
            $this->itemsStorage->getRole('author'),
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
        $this->assertSame('reader', $readerAssignment->getItemName());
        $this->assertSame(self::NOW, $readerAssignment->getCreatedAt());

        $this->assertSame('readingAuthor', $authorAssignment->getUserId());
        $this->assertSame('author', $authorAssignment->getItemName());
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
            $this->itemsStorage->getRole('reader'),
            'reader A'
        );
    }

    public function testAssignPermissionDirectlyWhenItIsDisabled(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Assigning permissions directly is disabled. Prefer assigning roles only.');

        $this->manager->assign(
            $this->itemsStorage->getPermission('updateAnyPost'),
            'reader'
        );
    }

    public function testAssignPermissionDirectlyWhenItIsEnabled(): void
    {
        $this->manager = $this->createManager($this->itemsStorage, $this->assignmentsStorage, true);

        $this->manager->assign(
            $this->itemsStorage->getPermission('updateAnyPost'),
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
        $this->assertSame(
            ['deletePost', 'createPost', 'updatePost', 'readPost'],
            array_keys($this->manager->getPermissionsByUser('author B'))
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
        $this->manager->removeRole('reader');
        $this->assertNull($this->itemsStorage->getRole('new role'));
    }

    public function testUpdateRoleNameAndRule(): void
    {
        $role = $this->itemsStorage->getRole('reader')->withName('new reader');
        $this->manager->updateRole('reader', $role);

        $this->assertNull($this->itemsStorage->getRole('reader'));
        $this->assertNotNull($this->itemsStorage->getRole('new reader'));
    }

    public function testAddPermission(): void
    {
        $permission = (new Permission('edit post'))
            ->withDescription('edit a post')
            ->withCreatedAt(1642026147)
            ->withUpdatedAt(1642026148);

        $this->manager->addPermission($permission);

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
        $permission = new Permission('test');
        $this->manager->addPermission($permission);

        $storedPermission = $this->itemsStorage->getPermission('test');

        $this->assertNotNull($storedPermission);
        $this->assertNotNull($storedPermission->getCreatedAt());
        $this->assertNotNull($storedPermission->getUpdatedAt());
    }

    public function testRemovePermission(): void
    {
        $this->manager->removePermission('updatePost');
        $this->assertNull($this->itemsStorage->getPermission('updatePost'));
    }

    public function testUpdatePermission(): void
    {
        $permission = $this->itemsStorage->getPermission('updatePost')
            ->withName('newUpdatePost')
            ->withCreatedAt(1642026149)
            ->withUpdatedAt(1642026150);

        $this->manager->updatePermission('updatePost', $permission);

        $this->assertNull($this->itemsStorage->getPermission('updatePost'));
        $newPermission = $this->itemsStorage->getPermission('newUpdatePost');
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

        $permission = $this->itemsStorage->getPermission('updatePost')
            ->withName('createPost');

        $this->manager->updatePermission('updatePost', $permission);
    }

    public function testAddRule(): void
    {
        $ruleName = 'isReallyReallyAuthor';
        $rule = new AuthorRule($ruleName, true);

        $this->manager->addRule($rule);

        $rule = $this->itemsStorage->getRule($ruleName);
        $this->assertEquals($ruleName, $rule->getName());
        $this->assertTrue($rule->isReallyReally());
    }

    public function testRemoveRule(): void
    {
        $this->manager->removeRule(
            $this->itemsStorage->getRule('isAuthor')
        );

        $this->assertNull($this->itemsStorage->getRule('isAuthor'));
    }

    public function testUpdateRule(): void
    {
        $rule = $this->itemsStorage->getRule('isAuthor')
            ->withName('newName')
            ->withReallyReally(false);

        $this->manager->updateRule('isAuthor', $rule);
        $this->assertNull($this->itemsStorage->getRule('isAuthor'));
        $this->assertNotNull($this->itemsStorage->getRule('newName'));
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
        ItemsStorageInterface $itemsStorage,
        AssignmentsStorageInterface $assignmentsStorage,
        bool $enableDirectPermissions = false
    ): Manager {
        return (new Manager($itemsStorage, $assignmentsStorage, new ClassNameRuleFactory(), $enableDirectPermissions))
            ->setDefaultRoleNames(['myDefaultRole']);
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

        $storage->addChild('reader', 'readPost');
        $storage->addChild('author', 'createPost');
        $storage->addChild('author', 'updatePost');
        $storage->addChild('author', 'reader');
        $storage->addChild('admin', 'author');
        $storage->addChild('admin', 'updateAnyPost');

        $storage->addRule(new AuthorRule('isAuthor'));

        return $storage;
    }

    private function createAssignmentsStorage(): AssignmentsStorageInterface
    {
        $storage = new FakeAssignmentsStorage(self::NOW);

        $storage->add('reader A', 'Fast Metabolism');
        $storage->add('reader A', 'reader');
        $storage->add('author B', 'author');
        $storage->add('author B', 'deletePost');
        $storage->add('admin C', 'admin');

        return $storage;
    }

    public function testRevokeRole(): void
    {
        $this->manager->revoke(
            $this->itemsStorage->getRole('reader'),
            'reader A'
        );

        $this->assertEquals(['Fast Metabolism'], array_keys($this->assignmentsStorage->getUserAssignments('reader A')));
    }

    public function testRevokePermission(): void
    {
        $this->manager->revoke(
            $this->itemsStorage->getPermission('deletePost'),
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
