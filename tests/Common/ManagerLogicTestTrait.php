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
            ->addRole(new Role('guest'))
            ->setGuestRoleName('guest')
            ->addPermission(
                (new Permission('updateIssue'))->withRuleName('isAuthor'),
            )
            ->addChild('guest', 'updateIssue')
            ->assign('guest', userId: 1);

        $this->assertSame($expectedUserHasPermission, $manager->userHasPermission($userId, 'updateIssue', $parameters));
    }

    public function dataUserHasPermission(): array
    {
        $warnedUserId = 1;
        $trialUserId = 2;
        $activeSubscriptionUserId = 3;
        $inActiveSubscriptionUserId = 4;
        $explicitGuestUserId = 5;

        return [
            ['reader A', 'createPost', ['authorID' => 'author B'], false],
            ['reader A', 'readPost', ['authorID' => 'author B'], true],
            ['reader A', 'updatePost', ['authorID' => 'author B'], false],
            ['reader A', 'updateAnyPost', ['authorID' => 'author B'], false],
            ['reader A', 'reader', ['authorID' => 'author B'], false],

            ['author B', 'createPost', ['authorID' => 'author B'], true],
            ['author B', 'readPost', ['authorID' => 'author B'], true],
            ['author B', 'updatePost', ['authorID' => 'author B'], true],
            ['author B', 'deletePost', ['authorID' => 'author B'], true],
            ['author B', 'updateAnyPost', ['authorID' => 'author B'], false],

            ['admin C', 'createPost', ['authorID' => 'author B'], true],
            ['admin C', 'readPost', ['authorID' => 'author B'], true],
            ['admin C', 'updatePost', ['authorID' => 'author B'], false],
            ['admin C', 'updateAnyPost', ['authorID' => 'author B'], true],
            ['admin C', 'nonExistingPermission', ['authorID' => 'author B'], false],

            ['guest', 'createPost', ['authorID' => 'author B'], false],
            ['guest', 'readPost', ['authorID' => 'author B'], false],
            ['guest', 'updatePost', ['authorID' => 'author B'], false],
            ['guest', 'deletePost', ['authorID' => 'author B'], false],
            ['guest', 'updateAnyPost', ['authorID' => 'author B'], false],
            ['guest', 'blablabla', ['authorID' => 'author B'], false],

            [12, 'createPost', ['authorID' => 'author B'], false],
            [12, 'readPost', ['authorID' => 'author B'], false],
            [12, 'updatePost', ['authorID' => 'author B'], false],
            [12, 'deletePost', ['authorID' => 'author B'], false],
            [12, 'updateAnyPost', ['authorID' => 'author B'], false],
            [12, 'blablabla', ['authorID' => 'author B'], false],

            [null, 'createPost', ['authorID' => 'author B'], false],
            [null, 'readPost', ['authorID' => 'author B'], false],
            [null, 'updatePost', ['authorID' => 'author B'], false],
            [null, 'deletePost', ['authorID' => 'author B'], false],
            [null, 'updateAnyPost', ['authorID' => 'author B'], false],
            [null, 'blablabla', ['authorID' => 'author B'], false],

            [null, 'guest', [], false],
            [null, 'view ads', [], true],
            [null, 'view regular content', [], true],
            [null, 'view news', [], true],
            [null, 'view exclusive content', [], false],
            [null, 'view ban warning', [], false],

            // https://github.com/yiisoft/rbac/issues/172

            [null, 'view ads', ['dayPeriod' => 'morning'], true],
            [null, 'view ads', ['dayPeriod' => 'night'], false],
            [$explicitGuestUserId, 'view ads', [], true],
            [$explicitGuestUserId, 'view ads', ['dayPeriod' => 'morning'], true],
            [$explicitGuestUserId, 'view ads', ['dayPeriod' => 'night'], false],

            [$activeSubscriptionUserId, 'view exclusive content', [], true],
            [$inActiveSubscriptionUserId, 'view exclusive content', [], false],
            [$activeSubscriptionUserId, 'view exclusive content', ['voidSubscription' => true], false],
        ];
    }

    /**
     * @link https://github.com/yiisoft/rbac/issues/193
     * @dataProvider dataUserHasPermission
     */
    public function testUserHasPermission(
        int|string|null $userId,
        string $permissionName,
        array $parameters,
        bool $expectedHasPermission,
    ): void {
        // view ban warning - check if warning was already viewed
        // guests - restrict access in a certain period of time

        $warnedUserId = 1;
        $trialUserId = 2;
        $activeSubscriptionUserId = 3;
        $inActiveSubscriptionUserId = 4;
        $explicitGuestUserId = 5;
        $manager = $this->createFilledManager()
            ->addRole(new Role('guest'))
            ->setGuestRoleName('guest')
            ->addRole(new Role('warned user'))
            ->addRole(new Role('trial user'))
            ->addRole((new Role('subscribed user'))->withRuleName('subscription'))
            ->addPermission((new Permission('view ads'))->withRuleName('ads'))
            ->addPermission(new Permission('view ban warning'))
            ->addPermission(new Permission('view content'))
            ->addPermission(new Permission('view regular content'))
            ->addPermission(new Permission('view news'))
            ->addPermission(new Permission('view wiki'))
            ->addPermission(new Permission('view exclusive content'))
            ->addChild('warned user', 'guest')
            ->addChild('trial user', 'guest')
            ->addChild('trial user', 'subscribed user')
            ->addChild('view content', 'view regular content')
            ->addChild('view content', 'view exclusive content')
            ->addChild('view regular content', 'view news')
            ->addChild('view regular content', 'view wiki')
            ->addChild('guest', 'view ads')
            ->addChild('guest', 'view regular content')
            ->addChild('warned user', 'view ban warning')
            ->addChild('subscribed user', 'view content')
            ->assign('warned user', $warnedUserId)
            ->assign('trial user', $trialUserId)
            ->assign('subscribed user', $activeSubscriptionUserId)
            ->assign('subscribed user', $inActiveSubscriptionUserId)
            ->assign('guest', $explicitGuestUserId);

        $this->assertSame($expectedHasPermission, $manager->userHasPermission($userId, $permissionName, $parameters));
    }

    public function testUserHasPermissionWithImplicitGuestAndNonExistingGuestRole(): void
    {
        $manager = $this
            ->createFilledManager()
            ->addRole(new Role('non-existing-guest'))
            ->setGuestRoleName('non-existing-guest')
            ->removeRole('non-existing-guest');

        $this->assertFalse($manager->userHasPermission(null, 'readPost'));
    }

    public function testUserHasPermissionWuithNonExistingUserAndNoDefaultRoles(): void
    {
        $manager = $this->createFilledManager();
        $manager->setDefaultRoleNames([]);

        $this->assertFalse($manager->userHasPermission('unknown user', 'createPost'));
    }

    public function testUserHasPermissionWithNonExistingRule(): void
    {
        $manager = $this
            ->createFilledManager()
            ->addPermission((new Permission('test-permission'))->withRuleName('non-existing-rule'))
            ->addRole(new Role('test'))
            ->addChild('test', 'test-permission')
            ->assign('test-permission', 'reader A');

        $this->expectException(RuleNotFoundException::class);
        $this->expectExceptionMessage('Rule "non-existing-rule" not found.');
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

        $this->assertTrue($manager->hasChild('reader', 'createPost'));
        $this->assertTrue($manager->hasChild('reader', 'readPost'));
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

        $this->assertFalse($manager->hasChild('author', 'createPost'));
        $this->assertTrue($manager->hasChild('author', 'updatePost'));
        $this->assertTrue($manager->hasChild('author', 'reader'));
        $this->assertSame($manager, $returnedManager);
    }

    public function testRemoveChildren(): void
    {
        $manager = $this->createFilledManager();
        $returnedManager = $manager->removeChildren('author');

        $this->assertFalse($manager->hasChildren('author'));
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
        $manager = $this->createFilledManager()->assign('updateAnyPost', 'reader');

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

        $storedRole = $manager->getRole('new role');

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

        $this->assertNull($manager->getRole('reader'));
        $this->assertSame($manager, $returnedManager);
        $this->assertFalse($manager->userHasPermission('reader A', 'readPost'));
    }

    public function testUpdateRoleNameAndRule(): void
    {
        $manager = $this->createFilledManager();
        $role = $manager
            ->getRole('reader')
            ->withName('new reader');
        $returnedManager = $manager->updateRole('reader', $role);

        $this->assertNull($manager->getRole('reader'));
        $this->assertNotNull($manager->getRole('new reader'));
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
        $storedPermission = $manager->getPermission('edit post');

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
        $storedPermission = $manager->getPermission('test');

        $this->assertNotNull($storedPermission);
        $this->assertNotNull($storedPermission->getCreatedAt());
        $this->assertNotNull($storedPermission->getUpdatedAt());
    }

    public function testRemovePermission(): void
    {
        $manager = $this->createFilledManager();
        $returnedManager = $manager->removePermission('deletePost');

        $this->assertNull($manager->getPermission('deletePost'));
        $this->assertSame($manager, $returnedManager);
        $this->assertFalse($manager->userHasPermission('author B', 'deletePost'));
    }

    public function testUpdatePermission(): void
    {
        $manager = $this->createFilledManager();
        $permission = $manager
            ->getPermission('updatePost')
            ->withName('newUpdatePost')
            ->withCreatedAt(1_642_026_149)
            ->withUpdatedAt(1_642_026_150);
        $returnedManager = $manager->updatePermission('updatePost', $permission);

        $this->assertNull($manager->getPermission('updatePost'));
        $newPermission = $manager->getPermission('newUpdatePost');
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
        $permission = $manager
            ->getPermission('deletePost')
            ->withName('newDeletePost')
            ->withCreatedAt(1_642_026_149)
            ->withUpdatedAt(1_642_026_150);
        $manager->updatePermission('deletePost', $permission);
        $newPermission = $manager->getPermission('newDeletePost');

        $this->assertNull($manager->getPermission('deletePost'));
        $this->assertNotNull($newPermission);
        $this->assertSame(1_642_026_149, $newPermission->getCreatedAt());
        $this->assertSame(1_642_026_150, $newPermission->getUpdatedAt());
        $this->assertFalse($manager->userHasPermission('author B', 'deletePost'));
        $this->assertTrue($manager->userHasPermission('author B', 'newDeletePost'));
    }

    public function testUpdatePermissionNameAlreadyUsed(): void
    {
        $manager = $this->createFilledManager();
        $permission = $manager->getPermission('updatePost')->withName('createPost');

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
        $role = $manager->getRole('reader')->withName('author');

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
        $manager = $this
            ->createManager()
            ->addRole(new Role('a'))
            ->addRole(new Role('b'));
        $returnedManager = $manager->setDefaultRoleNames(['a', 'b']);

        $this->assertSame(['a', 'b'], $manager->getDefaultRoleNames());
        $this->assertSame($manager, $returnedManager);
    }

    public function testDefaultRolesSetWithClosure(): void
    {
        $manager = $this->createFilledManager()->addRole(new Role('newDefaultRole'));
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

        foreach ($defaultRoleNames as $roleName) {
            $manager->addRole(new Role($roleName));
        }

        $manager->setDefaultRoleNames($defaultRoleNames);

        foreach ($defaultRoleNames as $roleName) {
            $manager->removeRole($roleName);
        }

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage($expectedExceptionMessage);
        $manager->getDefaultRoles();
    }

    public function testRevokeRole(): void
    {
        $manager = $this->createFilledManager();
        $this->assertArrayHasKey('reader', $manager->getRolesByUserId('reader A'));

        $returnedManager = $manager->revoke('reader', 'reader A');
        $this->assertArrayNotHasKey('reader', $manager->getRolesByUserId('reader A'));
        $this->assertSame($manager, $returnedManager);
    }

    public function testRevokePermission(): void
    {
        $manager = $this->createFilledManager();
        $this->assertArrayHasKey('deletePost', $manager->getPermissionsByUserId('author B'));

        $manager->revoke('deletePost', 'author B');
        $this->assertArrayNotHasKey('deletePost', $manager->getPermissionsByUserId('author B'));
    }

    public function testRevokeAll(): void
    {
        $manager = $this->createFilledManager();
        $this->assertNotEmpty($manager->getPermissionsByUserId('author B'));

        $returnedManager = $manager->revokeAll('author B');
        $this->assertEmpty($manager->getPermissionsByUserId('author B'));
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
