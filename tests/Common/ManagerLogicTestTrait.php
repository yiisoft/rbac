<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Common;

use Closure;
use DateTimeImmutable;
use InvalidArgumentException;
use RuntimeException;
use Yiisoft\Rbac\Assignment;
use Yiisoft\Rbac\Exception\DefaultRolesNotFoundException;
use Yiisoft\Rbac\Exception\ItemAlreadyExistsException;
use Yiisoft\Rbac\Exception\RuleInterfaceNotImplementedException;
use Yiisoft\Rbac\Exception\RuleNotFoundException;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\Role;
use Yiisoft\Rbac\RuleInterface;
use Yiisoft\Rbac\Tests\Support\AdsRule;
use Yiisoft\Rbac\Tests\Support\AuthorRule;
use Yiisoft\Rbac\Tests\Support\BanRule;
use Yiisoft\Rbac\Tests\Support\FakeAssignmentsStorage;
use Yiisoft\Rbac\Tests\Support\FakeItemsStorage;
use Yiisoft\Rbac\Tests\Support\FalseRule;
use Yiisoft\Rbac\Tests\Support\GuestRule;
use Yiisoft\Rbac\Tests\Support\SubscriptionRule;
use Yiisoft\Rbac\Tests\Support\TrueRule;
use Yiisoft\Rbac\Tests\Support\WannabeRule;

trait ManagerLogicTestTrait
{
    public static function dataUserHasPermissionGeneric(): array
    {
        return [
            ['reader A', 'createPost', [], false],
            ['reader A', 'readPost', [], true],
            ['reader A', 'updatePost', ['authorId' => 'author B'], false],
            ['reader A', 'updateAnyPost', [], false],
            ['reader A', 'reader', [], false],

            ['author B', 'createPost', [], true],
            ['author B', 'readPost', [], true],
            ['author B', 'updatePost', ['authorId' => 'author B'], true],
            ['author B', 'deletePost', [], true],
            ['author B', 'updateAnyPost', [], false],

            ['admin C', 'createPost', [], true],
            ['admin C', 'readPost', [], true],
            ['admin C', 'updatePost', ['authorId' => 'author B'], false],
            ['admin C', 'updateAnyPost', [], true],
            ['admin C', 'nonExistingPermission', [], false],

            ['guest', 'createPost', [], false],
            ['guest', 'readPost', [], false],
            ['guest', 'updatePost', ['authorId' => 'author B'], false],
            ['guest', 'deletePost', [], false],
            ['guest', 'updateAnyPost', [], false],
            ['guest', 'blablabla', [], false],

            [12, 'createPost', [], false],
            [12, 'readPost', [], false],
            [12, 'updatePost', ['authorId' => 'author B'], false],
            [12, 'deletePost', [], false],
            [12, 'updateAnyPost', [], false],
            [12, 'blablabla', [], false],

            [null, 'createPost', [], false],
            [null, 'readPost', [], false],
            [null, 'updatePost', ['authorId' => 'author B'], false],
            [null, 'deletePost', [], false],
            [null, 'updateAnyPost', [], false],
            [null, 'blablabla', [], false],
        ];
    }

    /**
     * @dataProvider dataUserHasPermissionGeneric
     */
    public function testUserHasPermissionGeneric(
        int|string|null $userId,
        string $permissionName,
        array $parameters,
        bool $expectedHasPermission,
    ): void {
        $this->assertSame(
            $expectedHasPermission,
            $this->createFilledManager()->userHasPermission($userId, $permissionName, $parameters),
        );
    }

    public static function dataUserHasPermissionGuestOriented(): array
    {
        $warnedUserId = 1;
        $trialUserId = 2;
        $activeSubscriptionUserId = 3;
        $inActiveSubscriptionUserId = 4;
        $explicitGuestUserId = 5;

        return [
            [null, 'guest', [], false],
            [null, 'view ads', [], true],
            [null, 'view regular content', [], true],
            [null, 'view news', [], true],
            [null, 'view exclusive content', [], false],
            [null, 'view ban warning', [], false],

            [null, 'view ads', ['dayPeriod' => 'morning'], true],
            [null, 'view ads', ['dayPeriod' => 'night'], false],
            [$explicitGuestUserId, 'view ads', [], true],
            [$explicitGuestUserId, 'view ads', ['dayPeriod' => 'morning'], true],
            [$explicitGuestUserId, 'view ads', ['dayPeriod' => 'night'], false],

            [null, 'edit news comment', ['authorId' => null], false],
            [null, 'edit news comment', ['authorId' => $explicitGuestUserId], false],
            [$explicitGuestUserId, 'edit news comment', ['authorId' => null], false],
            [$explicitGuestUserId, 'edit news comment', ['authorId' => 55], false],
            [$explicitGuestUserId, 'edit news comment', ['authorId' => $explicitGuestUserId], true],
            [$explicitGuestUserId, 'edit news comment', ['authorId' => (string) $explicitGuestUserId], true],
            [(string) $explicitGuestUserId, 'edit news comment', ['authorId' => $explicitGuestUserId], true],
            [(string) $explicitGuestUserId, 'edit news comment', ['authorId' => (string) $explicitGuestUserId], true],

            [null, 'view news', ['noGuestsModeOn' => true], false],
            [
                $explicitGuestUserId,
                'edit news comment',
                ['authorId' => $explicitGuestUserId, 'noGuestsModeOn' => true],
                false,
            ],

            [$warnedUserId, 'view ban warning', [], true],
            [$warnedUserId, 'view ban warning', ['viewed' => true], false],

            [$trialUserId, 'view ads', [], true],
            [$trialUserId, 'view ads', [], true],
            [$activeSubscriptionUserId, 'view ads', [], false],
            [$inActiveSubscriptionUserId, 'view ads', [], false],

            [$activeSubscriptionUserId, 'view exclusive content', [], true],
            [$inActiveSubscriptionUserId, 'view exclusive content', [], false],
            [$activeSubscriptionUserId, 'view exclusive content', ['voidSubscription' => true], false],
        ];
    }

    /**
     * @link https://github.com/yiisoft/rbac/issues/172
     * @link https://github.com/yiisoft/rbac/issues/193
     * @dataProvider dataUserHasPermissionGuestOriented
     */
    public function testUserHasPermissionGuestOriented(
        int|string|null $userId,
        string $permissionName,
        array $parameters,
        bool $expectedHasPermission,
    ): void {
        $warnedUserId = 1;
        $trialUserId = 2;
        $activeSubscriptionUserId = 3;
        $inActiveSubscriptionUserId = 4;
        $explicitGuestUserId = 5;
        $manager = $this
            ->createManager(
                $this->createItemsStorage(),
                $this->createAssignmentsStorage(),
                enableDirectPermissions: true,
            )
            ->addRole((new Role('guest'))->withRuleName(GuestRule::class))
            ->setGuestRoleName('guest')
            ->addRole(new Role('news comment manager'))
            ->addRole(new Role('warned user'))
            ->addRole(new Role('trial user'))
            ->addRole((new Role('subscribed user'))->withRuleName(SubscriptionRule::class))
            ->addPermission((new Permission('view ads'))->withRuleName(AdsRule::class))
            ->addPermission((new Permission('view ban warning'))->withRuleName(BanRule::class))
            ->addPermission(new Permission('view content'))
            ->addPermission(new Permission('view regular content'))
            ->addPermission(new Permission('view news'))
            ->addPermission(new Permission('add news comment'))
            ->addPermission(new Permission('view news comment'))
            ->addPermission((new Permission('edit news comment'))->withRuleName(AuthorRule::class))
            ->addPermission((new Permission('remove news comment'))->withRuleName(AuthorRule::class))
            ->addPermission(new Permission('view wiki'))
            ->addPermission(new Permission('view exclusive content'))
            ->addChild('view content', 'view regular content')
            ->addChild('view content', 'view exclusive content')
            ->addChild('view regular content', 'view news')
            ->addChild('view regular content', 'view wiki')
            ->addChild('news comment manager', 'add news comment')
            ->addChild('news comment manager', 'view news comment')
            ->addChild('news comment manager', 'edit news comment')
            ->addChild('news comment manager', 'remove news comment')
            ->addChild('warned user', 'guest')
            ->addChild('trial user', 'guest')
            ->addChild('trial user', 'subscribed user')
            ->addChild('guest', 'view ads')
            ->addChild('guest', 'view regular content')
            ->addChild('guest', 'news comment manager')
            ->addChild('warned user', 'view ban warning')
            ->addChild('subscribed user', 'view content')
            ->addChild('subscribed user', 'news comment manager')
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

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Guest role with name "non-existing-guest" does not exist.');
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

    public function testUserHasPermissionWithRuleMissingImplements(): void
    {
        $className = WannabeRule::class;
        $interfaceName = RuleInterface::class;
        $manager = $this
            ->createFilledManager()
            ->addPermission((new Permission('test-permission'))->withRuleName($className))
            ->addRole(new Role('test'))
            ->addChild('test', 'test-permission')
            ->assign('test-permission', 'reader A');

        $this->expectException(RuleInterfaceNotImplementedException::class);
        $this->expectExceptionMessage("Rule \"$className\" must implement \"$interfaceName\".");
        $manager->userHasPermission('reader A', 'test-permission');
    }

    public static function dataUserHasPermissionWithRolesAllowed(): array
    {
        return [
            ['reader A', 'reader', true],
            ['reader A', 'admin', false],
            ['reader A', 'non-existing', false],
            ['admin C', 'reader', true],
        ];
    }

    /**
     * @dataProvider dataUserHasPermissionWithRolesAllowed
     */
    public function testUserHasPermissionWithRolesAllowed(
        string $userId,
        string $permissionName,
        bool $expectedHasPermission,
    ): void {
        $this->assertSame(
            $expectedHasPermission,
            $this->createFilledManager(includeRolesInAccessChecks: true)->userHasPermission($userId, $permissionName),
        );
    }

    public function testUserHasPermissionWithOneHierarchyBranch(): void
    {
        $manager = $this
            ->createFilledManager()
            ->addPermission(new Permission('Permission'))
            ->addRole(new Role('Role 1'))
            ->addRole((new Role('Role 2'))->withRuleName(FalseRule::class))
            ->addChild('Role 1', 'Permission')
            ->addChild('Role 2', 'Permission')
            ->assign(itemName: 'Role 1', userId: 'User')
            ->assign(itemName: 'Role 2', userId: 'User');

        $this->assertTrue($manager->userHasPermission('User', 'Permission'));
    }

    public static function dataUserHasPermissionWithDefaultRoles(): array
    {
        return [
            'child permission of default role' => [null, 'User', 'Permission 1', true],
            'nested child permission of default role' => [null, 'User', 'Permission 2.1.1', true],
            'nested child permission of default role, other nodes' => [null, 'User', 'Permission 2.2.1', true],
            'default role with children' => [null, 'User', 'Role 1', false],
            'default role without children' => [null, 'User', 'Role 3', false],
            'default role with children, roles are allowed in access checks' => [true, 'User', 'Role 1', true],
            'default role with nested children, roles are allowed in access checks' => [true, 'User', 'Role 2', true],
            'default role without children, roles are allowed in access checks' => [true, 'User', 'Role 3', true],
            'multple nested permissions, additionally assigned manually' => [false, 'User', 'Permission 4.1.1', true],
        ];
    }

    /**
     * @dataProvider dataUserHasPermissionWithDefaultRoles
     */
    public function testUserHasPermissionWithDefaultRoles(
        ?bool $includeRolesInAccessChecks,
        string $userId,
        string $permissionName,
        bool $expectedUserHasPermission,
    ): void {
        $manager = $this
            ->createManager(enableDirectPermissions: true, includeRolesInAccessChecks: $includeRolesInAccessChecks)
            ->addRole(new Role('Role 1'))
            ->addRole(new Role('Role 2'))
            ->addRole(new Role('Role 3'))
            ->addRole(new Role('Role 4'))
            ->setDefaultRoleNames(['Role 1', 'Role 2', 'Role 3', 'Role 4'])
            ->addPermission(new Permission('Permission 1'))
            ->addPermission(new Permission('Permission 2.1'))
            ->addPermission(new Permission('Permission 2.1.1'))
            ->addPermission(new Permission('Permission 2.1.2'))
            ->addPermission(new Permission('Permission 2.2'))
            ->addPermission(new Permission('Permission 2.2.1'))
            ->addPermission(new Permission('Permission 2.2.2'))
            ->addPermission(new Permission('Permission 4.1'))
            ->addPermission(new Permission('Permission 4.1.1'))
            ->addChild('Role 1', 'Permission 1')
            ->addChild('Role 2', 'Permission 2.1')
            ->addChild('Role 2', 'Permission 2.2')
            ->addChild('Permission 2.1', 'Permission 2.1.1')
            ->addChild('Permission 2.1', 'Permission 2.1.2')
            ->addChild('Permission 2.2', 'Permission 2.2.1')
            ->addChild('Permission 2.2', 'Permission 2.2.2')
            ->addChild('Role 4', 'Permission 4.1')
            ->addChild('Permission 4.1', 'Permission 4.1.1')
            ->assign(itemName: 'Permission 4.1', userId: 'User')
            ->assign(itemName: 'Permission 4.1.1', userId: 'User');
        $this->assertSame($expectedUserHasPermission, $manager->userHasPermission($userId, $permissionName));
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
        $manager = $this->createManager($itemsStorage)->addRole(new Role('author'));

        $this->assertFalse($manager->canAddChild('admin', 'author'));
    }

    public function testCanAddNonExistingChild(): void
    {
        $itemsStorage = $this->createItemsStorage();
        $manager = $this->createManager($itemsStorage)->addRole(new Role('author'));

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

    public function testAssign(): void
    {
        $itemsStorage = $this->createItemsStorage();
        $assignmentsStorage = $this->createAssignmentsStorage();
        $manager = $this->createManager(
            $itemsStorage,
            $assignmentsStorage,
            currentDateTime: new DateTimeImmutable('2023-05-10 08:24:39')
        )
            ->addRole(new Role('author'))
            ->addRole(new Role('reader'))
            ->addRole(new Role('writer'))
            ->addRole(new Role('default-role'))
            ->setDefaultRoleNames(['default-role'])
            ->assign('reader', 'readingAuthor')
            ->assign('author', 'readingAuthor');

        $this->assertEqualsCanonicalizing(
            [
                'default-role',
                'reader',
                'author',
            ],
            array_keys($manager->getRolesByUserId('readingAuthor'))
        );

        $createdAt = 1_683_707_079;
        $readerAssignment = $assignmentsStorage->get('reader', 'readingAuthor');

        $this->assertSame('readingAuthor', $readerAssignment->getUserId());
        $this->assertSame('reader', $readerAssignment->getItemName());
        $this->assertSame($createdAt, $readerAssignment->getCreatedAt());

        $authorAssignment = $assignmentsStorage->get('author', 'readingAuthor');

        $this->assertSame('readingAuthor', $authorAssignment->getUserId());
        $this->assertSame('author', $authorAssignment->getItemName());
        $this->assertSame($createdAt, $authorAssignment->getCreatedAt());
    }

    public function testAssignUnknownItem(): void
    {
        $manager = $this->createFilledManager();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('There is no item named "nonExistRole".');

        $manager->assign(itemName: 'nonExistRole', userId: 'reader');
    }

    public function testAssignAlreadyAssignedItem(): void
    {
        $manager = $this->createFilledManager();
        $this->assertSame($manager, $manager->assign(itemName: 'reader', userId: 'reader A'));
    }

    public function testAssignPermissionDirectlyWhenItIsDisabled(): void
    {
        $manager = $this->createManager();
        $manager->addPermission(new Permission('readPost'));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Assigning permissions directly is disabled. Prefer assigning roles only.');
        $manager->assign(itemName: 'readPost', userId: 'id7');
    }

    public function testAssignPermissionDirectlyWhenEnabled(): void
    {
        $manager = $this->createFilledManager()->assign('updateAnyPost', 'reader');

        $this->assertTrue($manager->userHasPermission('reader', 'updateAnyPost'));
    }

    public function testGetItemsByUserId(): void
    {
        $this->assertEqualsCanonicalizing(
            ['myDefaultRole', 'reader', 'readPost', 'Fast Metabolism'],
            array_keys($this->createFilledManager()->getItemsByUserId('reader A'))
        );
    }

    public function testGetRolesByUserId(): void
    {
        $this->assertEqualsCanonicalizing(
            ['admin', 'author', 'myDefaultRole', 'reader'],
            array_keys($this->createFilledManager()->getRolesByUserId('admin C')),
        );
    }

    public function testGetChildRoles(): void
    {
        $this->assertEqualsCanonicalizing(
            ['reader', 'author'],
            array_keys($this->createFilledManager()->getChildRoles('admin'))
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

    public function testGetPermissionsByUserId(): void
    {
        $this->assertEqualsCanonicalizing(
            ['deletePost', 'publishPost', 'createPost', 'updatePost', 'readPost'],
            array_keys($this->createFilledManager()->getPermissionsByUserId('author B'))
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

        $rule = new TrueRule();

        $role = (new Role('new role'))
            ->withDescription('new role description')
            ->withRuleName(TrueRule::class)
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
                'rule_name' => TrueRule::class,
                'type' => 'role',
                'updated_at' => 1_642_026_148,
                'created_at' => 1_642_026_147,
            ],
            $storedRole->getAttributes()
        );
        $this->assertSame($manager, $returnedManager);
    }

    public function testAddPermissionWithExistingRole(): void
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
        $this->assertEqualsCanonicalizing([], $manager->getUserIdsByRoleName('reader'));
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
                'rule_name' => null,
                'type' => 'permission',
                'updated_at' => 1_642_026_148,
                'created_at' => 1_642_026_147,
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
        $assignmentsStorage = $this->createAssignmentsStorage();
        $manager = $this->createFilledManager(assignmentsStorage: $assignmentsStorage);
        $returnedManager = $manager->removePermission('deletePost');

        $this->assertNull($manager->getPermission('deletePost'));
        $this->assertSame($manager, $returnedManager);
        $this->assertFalse($manager->userHasPermission('author B', 'deletePost'));
        $this->assertEmpty($assignmentsStorage->getByItemNames(['deletePost']));
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
        $this->assertFalse($manager->userHasPermission('author B', 'updatePost', ['authorId' => 'author B']));
        $this->assertTrue($manager->userHasPermission('author B', 'newUpdatePost', ['authorId' => 'author B']));
    }

    public function testUpdateDirectPermission(): void
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

    public static function dataSetDefaultRoleNamesException(): array
    {
        return [
            [['test1', 2, 'test3'], InvalidArgumentException::class, 'Each role name must be a string.'],
            [
                static fn(): string => 'test',
                InvalidArgumentException::class,
                'Default role names closure must return an array.',
            ],
            [
                static fn(): array => ['test1', 2, 'test3'],
                InvalidArgumentException::class,
                'Each role name must be a string.',
            ],
        ];
    }

    /**
     * @dataProvider dataSetDefaultRoleNamesException
     */
    public function testSetDefaultRoleNamesException(
        mixed $defaultRoleNames,
        string $expectedExceptionClass,
        string $expectedExceptionMessage,
    ): void {
        $this->expectException($expectedExceptionClass);
        $this->expectExceptionMessage($expectedExceptionMessage);
        $this->createFilledManager()->setDefaultRoleNames($defaultRoleNames);
    }

    public static function dataSetDefaultRoleNames(): array
    {
        return [
            [['defaultRole1'], ['defaultRole1']],
            [['defaultRole1', 'defaultRole2'], ['defaultRole1', 'defaultRole2']],
            [static fn(): array => ['defaultRole1'], ['defaultRole1']],
            [static fn(): array => ['defaultRole1', 'defaultRole2'], ['defaultRole1', 'defaultRole2']],
            [[], []],
            [static fn(): array => [], []],
        ];
    }

    /**
     * @dataProvider dataSetDefaultRoleNames
     */
    public function testSetDefaultRoleNames(array|Closure $defaultRoleNames, array $expectedRoleNames): void
    {
        $manager = $this
            ->createFilledManager()
            ->addRole(new Role('defaultRole1'))
            ->addRole(new Role('defaultRole2'));
        $returnedManager = $manager->setDefaultRoleNames($defaultRoleNames);

        $this->assertEqualsCanonicalizing($expectedRoleNames, $manager->getDefaultRoleNames());
        $this->assertSame($manager, $returnedManager);
    }

    public static function dataGetDefaultRolesException(): array
    {
        return [
            [
                ['non-existing'],
                DefaultRolesNotFoundException::class,
                'The following default roles were not found: "non-existing".',
            ],
            [
                ['non-existing1', 'non-existing2'],
                DefaultRolesNotFoundException::class,
                'The following default roles were not found: "non-existing1", "non-existing2".',
            ],
        ];
    }

    /**
     * @dataProvider dataGetDefaultRolesException
     */
    public function testGetDefaultRolesException(
        array $defaultRoleNames,
        string $expectedExceptionClass,
        string $expectedExceptionMessage,
    ): void {
        $manager = $this->createManager();

        foreach ($defaultRoleNames as $roleName) {
            $manager->addRole(new Role($roleName));
        }

        $manager->setDefaultRoleNames($defaultRoleNames);

        foreach ($defaultRoleNames as $roleName) {
            $manager->removeRole($roleName);
        }

        $this->expectException($expectedExceptionClass);
        $this->expectExceptionMessage($expectedExceptionMessage);
        $manager->getDefaultRoles();
    }

    public static function dataGetDefaultRoles(): array
    {
        return [
            [[]],
            [['a']],
            [['a', 'b']],
        ];
    }

    /**
     * @dataProvider dataGetDefaultRoles
     */
    public function testGetDefaultRoles($defaultRoleNames): void
    {
        $manager = $this->createManager();
        $manager
            ->addRole(new Role('a'))
            ->addRole(new Role('b'))
            ->addRole(new Role('c'))
            ->setDefaultRoleNames($defaultRoleNames);

        $roles = $manager->getDefaultRoles();

        $this->assertCount(count($defaultRoleNames), $roles);
        $this->assertEqualsCanonicalizing($defaultRoleNames, array_keys($roles));

        foreach ($defaultRoleNames as $name) {
            $this->assertSame($name, $roles[$name]->getName());
        }
    }

    public function testSetGuestRoleNameException(): void
    {
        $manager = $this->createFilledManager();
        $manager->setGuestRoleName('non-existing');

        $this->assertSame($manager->getGuestRoleName(), 'non-existing');
    }

    public static function dataSetGuestRoleName(): array
    {
        return [
            ['guest'],
            [null],
            ['non-existing'],
        ];
    }

    /**
     * @dataProvider dataSetGuestRoleName
     */
    public function testSetGuestRoleName(?string $guestRoleName): void
    {
        $manager = $this
            ->createManager()
            ->addRole(new Role('guest'));
        $returnedManager = $manager->setGuestRoleName($guestRoleName);

        $this->assertSame($guestRoleName, $manager->getGuestRoleName());
        $this->assertSame($manager, $returnedManager);
    }

    public function testGetGuestRoleException(): void
    {
        $manager = $this->createFilledManager()->setGuestRoleName('non-existing');
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Guest role with name "non-existing" does not exist.');
        $manager->getGuestRole();
    }

    public static function dataGetGuestRole(): array
    {
        return [
            ['guest'],
            [null],
        ];
    }

    /**
     * @dataProvider dataGetGuestRole
     */
    public function testGetGuestRole(?string $guestRoleName): void
    {
        $manager = $this
            ->createManager()
            ->addRole(new Role('guest'))
            ->setGuestRoleName($guestRoleName);
        $this->assertEquals($guestRoleName, $manager->getGuestRole()?->getName());
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
        $manager = $this->createManager(
            $itemsStorage,
            $assignmentsStorage,
            currentDateTime: new DateTimeImmutable('2023-05-10 08:24:39'),
        );
        $manager
            ->addRole((new Role('role1'))->withCreatedAt(1_694_502_936)->withUpdatedAt(1_694_502_936))
            ->addRole((new Role('role2'))->withCreatedAt(1_694_502_976)->withUpdatedAt(1_694_502_976))
            ->addChild('role1', 'role2');
        $manager->assign(itemName: 'role1', userId: 1);
        $manager->assign(itemName: 'role2', userId: 2);

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
