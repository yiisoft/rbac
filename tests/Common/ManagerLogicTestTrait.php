<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Common;

use DateTime;
use InvalidArgumentException;
use RuntimeException;
use SlopeIt\ClockMock\ClockMock;
use Yiisoft\Rbac\Assignment;
use Yiisoft\Rbac\Exception\ItemAlreadyExistsException;
use Yiisoft\Rbac\Exception\RuleNotFoundException;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\Role;
use Yiisoft\Rbac\Tests\Support\EasyRule;
use Yiisoft\Rbac\Tests\Support\FakeAssignmentsStorage;
use Yiisoft\Rbac\Tests\Support\FakeItemsStorage;

trait ManagerLogicTestTrait
{
    private static array $frozenTimeTests = ['testAssign', 'testDataPersistency'];

    protected function setUp(): void
    {
        if (in_array($this->getName(), self::$frozenTimeTests, strict: true)) {
            ClockMock::freeze(new DateTime('2023-05-10 08:24:39'));
        }
    }

    protected function tearDown(): void
    {
        if (in_array($this->getName(), self::$frozenTimeTests, strict: true)) {
            ClockMock::reset();
        }
    }

    /**
     * @dataProvider dataProviderUserHasPermission
     */
    public function testUserHasPermission($user, array $tests): void
    {
        $manager = $this->createFilledManager();
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
        $manager = $this->createFilledManager();
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

    public function testUserHasPermissionWithGuestAndCustomRule(): void
    {
        $userId = 1;
        $manager = $this->createFilledManager()
            ->setGuestRoleName('guest')
            ->addPermission(
                (new Permission('viewIssue'))->withRuleName('easyTrue'),
            )
            ->addRole(new Role('guest'))
            ->addChild('guest', 'viewIssue')
            ->assign('guest', $userId);

        $this->assertTrue($manager->userHasPermission(null, 'viewIssue'));
        $this->assertTrue($manager->userHasPermission($userId, 'viewIssue'));
    }

    public function dataUserHasPermissionWithGuestAndCustomRuleWithParameters(): array
    {
        return [
            [null, ['authorID' => null], false],
            [null, ['authorID' => 1], false],
            [1, ['authorID' => null], false],
            [1, ['authorID' => 2], false],
            [1, ['authorID' => 1], true],
            [1, ['authorID' => '1'], true],
            ['1', ['authorID' => 1], true],
            ['1', ['authorID' => '1'], true],
        ];
    }

    /**
     * @dataProvider dataUserHasPermissionWithGuestAndCustomRuleWithParameters
     */
    public function testUserHasPermissionWithGuestAndCustomRuleWithParameters(
        mixed $userId,
        array $parameters,
        bool $expectedUserHasPermission,
    ): void {
        $manager = $this->createFilledManager()
            ->setGuestRoleName('guest')
            ->addPermission(
                (new Permission('updateIssue'))->withRuleName('isAuthor'),
            )
            ->addRole(new Role('guest'))
            ->addChild('guest', 'updateIssue')
            ->assign('guest', userId: 1);

        $this->assertSame($expectedUserHasPermission, $manager->userHasPermission($userId, 'updateIssue', $parameters));
    }

    public function testGuestRoleName(): void
    {
        $itemsStorage = $this->createItemsStorage();
        $itemsStorage->add(new Role('guest'));

        $manager = $this->createManager($itemsStorage);
        $returnedManager = $manager->setGuestRoleName('guest');

        $this->assertFalse($manager->userHasPermission(null, 'guest'));
        $this->assertSame($manager, $returnedManager);
    }

    public function testUserHasPermissionWithNonExistGuestRole(): void
    {
        $manager = $this->createFilledManager();
        $manager->setGuestRoleName('non-exist-guest');

        $this->assertFalse(
            $manager->userHasPermission(null, 'readPost')
        );
    }

    public function testUserHasPermissionReturnFalseForNonExistingUserAndNoDefaultRoles(): void
    {
        $manager = $this->createFilledManager();
        $manager->setDefaultRoleNames([]);

        $this->assertFalse($manager->userHasPermission('unknown user', 'createPost'));
    }

    public function testUserHasPermissionWithNonExistingRule(): void
    {
        $manager = $this->createFilledManager();

        $permission = (new Permission('test-permission'))->withRuleName('non-exist-rule');
        $role = (new Role('test'));
        $this->itemsStorage->add($role);
        $this->itemsStorage->add($permission);
        $this->itemsStorage->addChild('test', 'test-permission');

        $this->expectException(RuleNotFoundException::class);
        $this->expectExceptionMessage('Rule "non-exist-rule" not found.');
        $manager->userHasPermission('reader A', 'test-permission');
    }

    public function testCanAddExistingChild(): void
    {
        $manager = $this->createFilledManager();

        $this->assertFalse(
            $manager->canAddChild(
                'author',
                'reader',
            ),
        );
    }

    public function testCanAddChildDetectsLoops(): void
    {
        $manager = $this->createFilledManager();

        $this->assertFalse(
            $manager->canAddChild(
                'reader',
                'author',
            ),
        );
    }

    public function testCanAddChildPermissionToRole(): void
    {
        $manager = $this->createFilledManager();

        $this->assertFalse(
            $manager->canAddChild(
                'readPost',
                'reader',
            ),
        );
    }

    public function testCanAddChildToNonExistingItem(): void
    {
        $itemsStorage = $this->createItemsStorage();
        $itemsStorage->add(new Role('author'));

        $manager = $this->createManager($itemsStorage);

        $this->assertFalse($manager->canAddChild('admin', 'author'));
    }

    public function testCanAddNonExistingChild(): void
    {
        $itemsStorage = $this->createItemsStorage();
        $itemsStorage->add(new Role('author'));

        $manager = $this->createManager($itemsStorage);

        $this->assertFalse($manager->canAddChild('author', 'reader'));
    }

    public function testCanAddChild(): void
    {
        $manager = $this->createFilledManager();

        $this->assertTrue(
            $manager->canAddChild(
                'reader',
                'createPost',
            ),
        );
    }

    public function testAddChild(): void
    {
        $manager = $this->createFilledManager();
        $returnedManager = $manager->addChild('reader', 'createPost');

        $this->assertEqualsCanonicalizing(
            [
                'readPost',
                'createPost',
            ],
            array_keys($this->itemsStorage->getDirectChildren('reader'))
        );
        $this->assertSame($manager, $returnedManager);
    }

    public function testAddChildNotHasItem(): void
    {
        $manager = $this->createFilledManager();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Parent "new reader" does not exist.');

        $manager->addChild(
            'new reader',
            'createPost'
        );
    }

    public function testAddChildEqualName(): void
    {
        $manager = $this->createFilledManager();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Cannot add "createPost" as a child of itself.');

        $manager->addChild(
            'createPost',
            'createPost'
        );
    }

    public function testAddChildPermissionToRole(): void
    {
        $manager = $this->createFilledManager();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Can not add "reader" role as a child of "createPost" permission.');

        $manager->addChild(
            'createPost',
            'reader'
        );
    }

    public function testAddChildAlreadyAdded(): void
    {
        $manager = $this->createFilledManager();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The item "reader" already has a child "readPost".');

        $manager->addChild(
            'reader',
            'readPost'
        );
    }

    public function testAddChildDetectLoop(): void
    {
        $manager = $this->createFilledManager();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Cannot add "author" as a child of "reader". A loop has been detected.');

        $manager->addChild(
            'reader',
            'author',
        );
    }

    public function testAddChildWithNonExistingChild(): void
    {
        $manager = $this->createFilledManager();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Child "new reader" does not exist.');
        $manager->addChild('reader', 'new reader');
    }

    public function testRemoveChild(): void
    {
        $manager = $this->createFilledManager();
        $returnedManager = $manager->removeChild('author', 'createPost');

        $this->assertEqualsCanonicalizing(
            [
                'updatePost',
                'reader',
            ],
            array_keys($this->itemsStorage->getDirectChildren('author'))
        );
        $this->assertSame($manager, $returnedManager);
    }

    public function testRemoveChildren(): void
    {
        $manager = $this->createFilledManager();
        $returnedManager = $manager->removeChildren('author');

        $this->assertFalse($this->itemsStorage->hasChildren('author'));
        $this->assertSame($manager, $returnedManager);
    }

    public function testHasChild(): void
    {
        $manager = $this->createFilledManager();

        $this->assertTrue($manager->hasChild('author', 'createPost'));
        $this->assertFalse($manager->hasChild('reader', 'createPost'));
    }

    /**
     * Relies on {@see ClockMock} for testing timestamp. When using with other PHPUnit classes / traits, make sure to
     * call {@see setUp} and {@see tearDown} methods explicitly.
     */
    public function testAssign(): void
    {
        $itemsStorage = $this->createItemsStorage();
        $itemsStorage->add(new Role('author'));
        $itemsStorage->add(new Role('reader'));
        $itemsStorage->add(new Role('writer'));
        $itemsStorage->add(new Role('default-role'));

        $assignmentsStorage = $this->createAssignmentsStorage();

        $manager = $this->createManager($itemsStorage, $assignmentsStorage);
        $manager->setDefaultRoleNames(['default-role']);

        $manager->assign('reader', 'readingAuthor');
        $readerAssignment = $assignmentsStorage->get('reader', 'readingAuthor');

        $manager->assign('author', 'readingAuthor');
        $authorAssignment = $assignmentsStorage->get('author', 'readingAuthor');

        $this->assertEqualsCanonicalizing(
            [
                'default-role',
                'reader',
                'author',
            ],
            array_keys($manager->getRolesByUserId('readingAuthor'))
        );

        $createdAt = 1_683_707_079;

        $this->assertSame('readingAuthor', $readerAssignment->getUserId());
        $this->assertSame('reader', $readerAssignment->getItemName());
        $this->assertSame($createdAt, $readerAssignment->getCreatedAt());

        $this->assertSame('readingAuthor', $authorAssignment->getUserId());
        $this->assertSame('author', $authorAssignment->getItemName());
        $this->assertSame($createdAt, $authorAssignment->getCreatedAt());
    }

    public function testAssignUnknownItem(): void
    {
        $manager = $this->createFilledManager();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('There is no item named "nonExistRole".');

        $manager->assign(
            'nonExistRole',
            'reader'
        );
    }

    public function testAssignAlreadyAssignedItem(): void
    {
        $manager = $this->createFilledManager();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('"reader" role has already been assigned to user reader A.');

        $manager->assign(
            'reader',
            'reader A'
        );
    }

    public function testAssignPermissionDirectlyWhenItIsDisabled(): void
    {
        $manager = $this->createManager(null, null, null, null);
        $manager->addPermission(new Permission('readPost'));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Assigning permissions directly is disabled. Prefer assigning roles only.');
        $manager->assign('readPost', 'id7');
    }

    public function testAssignPermissionDirectlyWhenItIsEnabled(): void
    {
        $manager = $this->createFilledManager(true);
        $manager->assign(
            'updateAnyPost',
            'reader'
        );

        $this->assertTrue($manager->userHasPermission('reader', 'updateAnyPost'));
    }

    public function testGetRolesByUser(): void
    {
        $manager = $this->createFilledManager();

        $this->assertEquals(
            ['myDefaultRole', 'reader'],
            array_keys($manager->getRolesByUserId('reader A'))
        );
    }

    public function testGetChildRoles(): void
    {
        $manager = $this->createFilledManager();

        $this->assertEqualsCanonicalizing(
            ['reader', 'author'],
            array_keys($manager->getChildRoles('admin'))
        );
    }

    public function testGetChildRolesWithNonExistingRole(): void
    {
        $manager = $this->createFilledManager();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Role "unknown" not found.');

        $manager->getChildRoles('unknown');
    }

    public function testGetPermissionsByRoleName(): void
    {
        $manager = $this->createFilledManager();

        $this->assertEqualsCanonicalizing(
            ['createPost', 'updatePost', 'readPost', 'updateAnyPost'],
            array_keys($manager->getPermissionsByRoleName('admin'))
        );

        $this->assertEmpty($manager->getPermissionsByRoleName('guest'));
    }

    public function testGetPermissionsByUser(): void
    {
        $manager = $this->createFilledManager();

        $this->assertEqualsCanonicalizing(
            ['deletePost', 'publishPost', 'createPost', 'updatePost', 'readPost'],
            array_keys($manager->getPermissionsByUserId('author B'))
        );
    }

    public function testGetPermissionsByUserForUserWithoutPermissions(): void
    {
        $manager = $this->createFilledManager();

        $this->assertSame(
            [],
            array_keys($manager->getPermissionsByUserId('guest'))
        );
    }

    public function testUserIdsByRole(): void
    {
        $manager = $this->createFilledManager();

        $this->assertEqualsCanonicalizing(
            [
                'reader A',
                'author B',
                'admin C',
            ],
            $manager->getUserIdsByRoleName('reader')
        );
        $this->assertEqualsCanonicalizing(
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
        $manager = $this->createFilledManager();

        $rule = new EasyRule();

        $role = (new Role('new role'))
            ->withDescription('new role description')
            ->withRuleName($rule->getName())
            ->withCreatedAt(1_642_026_147)
            ->withUpdatedAt(1_642_026_148);

        $returnedManager = $manager->addRole($role);

        $storedRole = $this->itemsStorage->getRole('new role');

        $this->assertNotNull($storedRole);
        $this->assertSame('new role description', $storedRole->getDescription());
        $this->assertSame(1_642_026_147, $storedRole->getCreatedAt());
        $this->assertSame(1_642_026_148, $storedRole->getUpdatedAt());
        $this->assertSame(
            [
                'name' => 'new role',
                'description' => 'new role description',
                'ruleName' => EasyRule::class,
                'type' => 'role',
                'updatedAt' => 1_642_026_148,
                'createdAt' => 1_642_026_147,
            ],
            $storedRole->getAttributes()
        );
        $this->assertSame($manager, $returnedManager);
    }

    public function testAddAlreadyExistsItem(): void
    {
        $manager = $this->createManager();
        $manager->addRole(new Role('reader'));

        $permission = new Permission('reader');

        $this->expectException(ItemAlreadyExistsException::class);
        $this->expectExceptionMessage('Role or permission with name "reader" already exists.');
        $manager->addPermission($permission);
    }

    public function testRemoveRole(): void
    {
        $manager = $this->createFilledManager();
        $returnedManager = $manager->removeRole('reader');

        $this->assertNull($this->itemsStorage->getRole('reader'));
        $this->assertSame($manager, $returnedManager);
        $this->assertFalse($manager->userHasPermission('reader A', 'readPost'));
    }

    public function testUpdateRoleNameAndRule(): void
    {
        $manager = $this->createFilledManager();
        $role = $this->itemsStorage
            ->getRole('reader')
            ->withName('new reader');
        $returnedManager = $manager->updateRole('reader', $role);

        $this->assertNull($this->itemsStorage->getRole('reader'));
        $this->assertNotNull($this->itemsStorage->getRole('new reader'));
        $this->assertSame($manager, $returnedManager);
        $this->assertTrue($manager->userHasPermission('reader A', 'readPost'));
    }

    public function testAddPermission(): void
    {
        $manager = $this->createFilledManager();
        $permission = (new Permission('edit post'))
            ->withDescription('edit a post')
            ->withCreatedAt(1_642_026_147)
            ->withUpdatedAt(1_642_026_148);
        $returnedManager = $manager->addPermission($permission);
        $storedPermission = $this->itemsStorage->getPermission('edit post');

        $this->assertNotNull($storedPermission);
        $this->assertSame('edit a post', $storedPermission->getDescription());
        $this->assertSame(1_642_026_147, $storedPermission->getCreatedAt());
        $this->assertSame(1_642_026_148, $storedPermission->getUpdatedAt());
        $this->assertSame(
            [
                'name' => 'edit post',
                'description' => 'edit a post',
                'ruleName' => null,
                'type' => 'permission',
                'updatedAt' => 1_642_026_148,
                'createdAt' => 1_642_026_147,
            ],
            $storedPermission->getAttributes()
        );
        $this->assertSame($manager, $returnedManager);
    }

    public function testAddPermissionWithoutTime(): void
    {
        $manager = $this->createFilledManager();
        $permission = new Permission('test');
        $manager->addPermission($permission);
        $storedPermission = $this->itemsStorage->getPermission('test');

        $this->assertNotNull($storedPermission);
        $this->assertNotNull($storedPermission->getCreatedAt());
        $this->assertNotNull($storedPermission->getUpdatedAt());
    }

    public function testRemovePermission(): void
    {
        $manager = $this->createFilledManager();
        $returnedManager = $manager->removePermission('deletePost');

        $this->assertNull($this->itemsStorage->getPermission('deletePost'));
        $this->assertSame($manager, $returnedManager);
        $this->assertFalse($manager->userHasPermission('author B', 'deletePost'));
    }

    public function testUpdatePermission(): void
    {
        $manager = $this->createFilledManager();
        $permission = $this->itemsStorage
            ->getPermission('updatePost')
            ->withName('newUpdatePost')
            ->withCreatedAt(1_642_026_149)
            ->withUpdatedAt(1_642_026_150);
        $returnedManager = $manager->updatePermission('updatePost', $permission);

        $this->assertNull($this->itemsStorage->getPermission('updatePost'));
        $newPermission = $this->itemsStorage->getPermission('newUpdatePost');
        $this->assertNotNull($newPermission);
        $this->assertSame(1_642_026_149, $newPermission->getCreatedAt());
        $this->assertSame(1_642_026_150, $newPermission->getUpdatedAt());
        $this->assertSame($manager, $returnedManager);
        $this->assertFalse($manager->userHasPermission('author B', 'updatePost', ['authorID' => 'author B']));
        $this->assertTrue($manager->userHasPermission('author B', 'newUpdatePost', ['authorID' => 'author B']));
    }

    public function testUpdateDirectPermission1(): void
    {
        $manager = $this->createFilledManager();
        $permission = $this->itemsStorage
            ->getPermission('deletePost')
            ->withName('newDeletePost')
            ->withCreatedAt(1_642_026_149)
            ->withUpdatedAt(1_642_026_150);
        $manager->updatePermission('deletePost', $permission);
        $newPermission = $this->itemsStorage->getPermission('newDeletePost');

        $this->assertNull($this->itemsStorage->getPermission('deletePost'));
        $this->assertNotNull($newPermission);
        $this->assertSame(1_642_026_149, $newPermission->getCreatedAt());
        $this->assertSame(1_642_026_150, $newPermission->getUpdatedAt());
        $this->assertFalse($manager->userHasPermission('author B', 'deletePost'));
        $this->assertTrue($manager->userHasPermission('author B', 'newDeletePost'));
    }

    public function testUpdatePermissionNameAlreadyUsed(): void
    {
        $manager = $this->createFilledManager();
        $permission = $this->itemsStorage
            ->getPermission('updatePost')
            ->withName('createPost');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Unable to change the role or the permission name. ' .
            'The name "createPost" is already used by another role or permission.'
        );
        $manager->updatePermission('updatePost', $permission);
    }

    public function testUpdateRoleNameAlreadyUsed(): void
    {
        $manager = $this->createFilledManager();
        $role = $this->itemsStorage
            ->getRole('reader')
            ->withName('author');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Unable to change the role or the permission name. ' .
            'The name "author" is already used by another role or permission.'
        );
        $manager->updateRole('reader', $role);
    }

    public function testSeveralDefaultRoles(): void
    {
        $manager = $this->createManager();
        $manager
            ->addRole(new Role('a'))
            ->addRole(new Role('b'))
            ->addRole(new Role('c'))
            ->setDefaultRoleNames(['a', 'b']);

        $roles = $manager->getDefaultRoles();

        $this->assertCount(2, $roles);
        $this->assertEqualsCanonicalizing(['a', 'b'], array_keys($roles));
        $this->assertSame('a', $roles['a']->getName());
        $this->assertSame('b', $roles['b']->getName());
    }

    public function testDefaultRoleNames(): void
    {
        $manager = $this->createManager();
        $returnedManager = $manager->setDefaultRoleNames(['a', 'b']);

        $this->assertSame(['a', 'b'], $manager->getDefaultRoleNames());
        $this->assertSame($manager, $returnedManager);
    }

    public function testDefaultRolesSetWithClosure(): void
    {
        $manager = $this->createFilledManager();
        $manager->setDefaultRoleNames(
            static function () {
                return ['newDefaultRole'];
            }
        );

        $this->assertEquals(['newDefaultRole'], $manager->getDefaultRoleNames());
    }

    public function testDefaultRolesWithClosureReturningNonArrayValue(): void
    {
        $manager = $this->createFilledManager();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Default role names closure must return an array');

        $manager->setDefaultRoleNames(
            static function () {
                return 'test';
            }
        );
    }

    public function testGetDefaultRoles(): void
    {
        $manager = $this->createFilledManager();

        $this->assertEquals(['myDefaultRole'], $manager->getDefaultRoleNames());
    }

    public function dataGetDefaultNonExistingRoles()
    {
        return [
            [['bananaCollector'], 'The following default roles were not found: "bananaCollector".'],
            [
                ['bananaCollector1', 'bananaCollector2'],
                'The following default roles were not found: "bananaCollector1", "bananaCollector2"',
            ],
        ];
    }

    /**
     * @dataProvider dataGetDefaultNonExistingRoles
     */
    public function testGetDefaultNonExistingRoles(array $defaultRoleNames, string $expectedExceptionMessage): void
    {
        $manager = $this->createManager();
        $manager->setDefaultRoleNames($defaultRoleNames);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage($expectedExceptionMessage);
        $manager->getDefaultRoles();
    }

    public function testRevokeRole(): void
    {
        $manager = $this->createFilledManager();
        $returnedManager = $manager->revoke(
            'reader',
            'reader A'
        );

        $this->assertSame(
            ['Fast Metabolism'],
            array_keys($this->assignmentsStorage->getByUserId('reader A'))
        );
        $this->assertSame($manager, $returnedManager);
    }

    public function testRevokePermission(): void
    {
        $manager = $this->createFilledManager();
        $manager->revoke(
            'deletePost',
            'author B'
        );

        $this->assertSame(
            ['author', 'publishPost'],
            array_keys($this->assignmentsStorage->getByUserId('author B'))
        );
    }

    public function testRevokeAll(): void
    {
        $manager = $this->createFilledManager();
        $returnedManager = $manager->revokeAll('author B');

        $this->assertEmpty($this->assignmentsStorage->getByUserId('author B'));
        $this->assertSame($manager, $returnedManager);
    }

    public function testDataPersistency(): void
    {
        $itemsStorage = new FakeItemsStorage();
        $assignmentsStorage = new FakeAssignmentsStorage();
        $manager = $this->createManager($itemsStorage, $assignmentsStorage);
        $manager
            ->addRole((new Role('role1'))->withCreatedAt(1_694_502_936)->withUpdatedAt(1_694_502_936))
            ->addRole((new Role('role2'))->withCreatedAt(1_694_502_976)->withUpdatedAt(1_694_502_976))
            ->addChild('role1', 'role2');
        $manager->assign('role1', 1);
        $manager->assign('role2', 2);

        $this->assertEquals(
            [
                'role1' => (new Role('role1'))->withCreatedAt(1_694_502_936)->withUpdatedAt(1_694_502_936),
                'role2' => (new Role('role2'))->withCreatedAt(1_694_502_976)->withUpdatedAt(1_694_502_976),
            ],
            $itemsStorage->getAll(),
        );
        $this->assertEquals(
            ['role2' => (new Role('role2'))->withCreatedAt(1_694_502_976)->withUpdatedAt(1_694_502_976)],
            $manager->getChildRoles('role1'),
        );
        $this->assertEquals(
            [
                '1' => ['role1' => new Assignment(userId: '1', itemName: 'role1', createdAt: 1_683_707_079)],
                '2' => ['role2' => new Assignment(userId: '2', itemName: 'role2', createdAt: 1_683_707_079)],
            ],
            $assignmentsStorage->getAll(),
        );
    }
}
