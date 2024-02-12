<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Common;

use DateTime;
use SlopeIt\ClockMock\ClockMock;
use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\ItemsStorageInterface;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\Role;
use Yiisoft\Rbac\Tests\Support\FakeItemsStorage;

trait ItemsStorageTestTrait
{
    private int $initialRolesCount = 0;
    private int $initialPermissionsCount = 0;
    private int $initialBothRolesChildrenCount = 0;
    private int $initialBothPermissionsChildrenCount = 0;
    private int $initialItemsChildrenCount = 0;

    private ?ItemsStorageInterface $itemsStorage = null;

    protected function setUp(): void
    {
        if ($this->name() === 'testAddWithCurrentTimestamps') {
            ClockMock::freeze(new DateTime('2023-05-10 08:24:39'));
        }

        if ($this->name() === 'testGetAccessTree') {
            ClockMock::freeze(new DateTime('2023-12-24 17:51:18'));
        }

        $this->populateItemsStorage();
    }

    protected function tearDown(): void
    {
        if (in_array($this->name(), ['testAddWithCurrentTimestamps', 'testGetAccessTree'], strict: true)) {
            ClockMock::reset();
        }

        $this->getItemsStorage()->clear();
    }

    public static function dataUpdate(): array
    {
        return [
            'present as parent in items children' => ['Parent 1', 'Super Admin', true],
            'no children' => ['Parent 3', 'Super Admin', false],
            'present as child in items children' => ['Child 1', 'Parent 1', true],
        ];
    }

    /**
     * @dataProvider dataUpdate
     */
    public function testUpdate(string $itemName, string $parentNameForChildrenCheck, bool $expectedHasChildren): void
    {
        $testStorage = $this->getItemsStorageForModificationAssertions();
        $actionStorage = $this->getItemsStorage();

        $item = $actionStorage->get($itemName);
        $this->assertNull($item->getRuleName());

        $item = $item
            ->withName('Super Admin')
            ->withRuleName('super admin');
        $actionStorage->update($itemName, $item);

        $this->assertNull($testStorage->get($itemName));

        $item = $testStorage->get('Super Admin');
        $this->assertNotNull($item);

        $this->assertSame('Super Admin', $item->getName());
        $this->assertSame('super admin', $item->getRuleName());

        $this->assertSame($expectedHasChildren, $testStorage->hasChildren($parentNameForChildrenCheck));
    }

    public function testGet(): void
    {
        $storage = $this->getItemsStorage();
        $item = $storage->get('Parent 3');

        $this->assertInstanceOf(Permission::class, $item);
        $this->assertSame(Item::TYPE_PERMISSION, $item->getType());
        $this->assertSame('Parent 3', $item->getName());
    }

    public function testGetWithNonExistingName(): void
    {
        $storage = $this->getItemsStorage();
        $this->assertNull($storage->get('Non-existing name'));
    }

    public static function dataExists(): array
    {
        return [
            ['Parent 1', true],
            ['Parent 2', true],
            ['Parent 3', true],
            ['Parent 100', false],
            ['Child 1', true],
            ['Child 2', true],
            ['Child 100', false],
        ];
    }

    /**
     * @dataProvider dataExists
     */
    public function testExists(string $name, bool $expectedExists): void
    {
        $storage = $this->getItemsStorage();
        $this->assertSame($expectedExists, $storage->exists($name));
    }

    public static function dataRoleExists(): array
    {
        return [
            ['posts.viewer', true],
            ['posts.view', false],
            ['non-existing', false],
        ];
    }

    /**
     * @dataProvider dataRoleExists
     */
    public function testRoleExists(string $name, bool $expectedRoleExists): void
    {
        $this->assertSame($expectedRoleExists, $this->getItemsStorage()->roleExists($name));
    }

    public function testGetPermission(): void
    {
        $storage = $this->getItemsStorage();
        $permission = $storage->getPermission('Child 1');

        $this->assertInstanceOf(Permission::class, $permission);
        $this->assertSame('Child 1', $permission->getName());
    }

    public function testAddChild(): void
    {
        $testStorage = $this->getItemsStorageForModificationAssertions();
        $actionStorage = $this->getItemsStorage();
        $actionStorage->addChild('Parent 2', 'Child 1');

        $children = $testStorage->getAllChildren('Parent 2');
        $this->assertCount(3, $children);

        foreach ($children as $name => $item) {
            $this->assertSame($name, $item->getName());
        }
    }

    public function testClear(): void
    {
        $testStorage = $this->getItemsStorageForModificationAssertions();
        $actionStorage = $this->getItemsStorage();
        $actionStorage->clear();

        $this->assertEmpty($testStorage->getAll());
    }

    public static function dataGetDirectChildren(): array
    {
        return [
            ['Parent 1', ['Child 1']],
            ['Parent 2', ['Child 2', 'Child 3']],
            ['posts.view', []],
            ['posts.create', []],
            ['posts.update', []],
            ['posts.delete', []],
            ['posts.viewer', ['posts.view']],
            ['posts.redactor', ['posts.viewer', 'posts.create', 'posts.update']],
            ['posts.admin', ['posts.redactor', 'posts.delete']],
            ['non-existing', []],
        ];
    }

    /**
     * @dataProvider dataGetDirectChildren
     */
    public function testGetDirectChildren(string $parentName, array $expectedChildren): void
    {
        $children = $this->getItemsStorage()->getDirectChildren($parentName);
        $this->assertChildren($children, $expectedChildren);
    }

    public static function dataGetAllChildren(): array
    {
        return [
            ['Parent 1', ['Child 1']],
            ['Parent 2', ['Child 2', 'Child 3']],
            ['posts.view', []],
            ['posts.create', []],
            ['posts.update', []],
            ['posts.delete', []],
            ['posts.viewer', ['posts.view']],
            ['posts.redactor', ['posts.viewer', 'posts.view', 'posts.create', 'posts.update']],
            [
                'posts.admin',
                ['posts.redactor', 'posts.viewer', 'posts.view', 'posts.create', 'posts.update', 'posts.delete'],
            ],
            [['Parent 1', 'Parent 2'], ['Child 1', 'Child 2', 'Child 3']],
            [
                ['posts.viewer', 'posts.redactor', 'posts.admin'],
                ['posts.view', 'posts.create', 'posts.update', 'posts.delete'],
            ],
            ['non-existing', []],
        ];
    }

    /**
     * @dataProvider dataGetAllChildren
     */
    public function testGetAllChildren(string|array $parentNames, array $expectedChildren): void
    {
        $children = $this->getItemsStorage()->getAllChildren($parentNames);
        $this->assertChildren($children, $expectedChildren);
    }

    public static function dataGetAllChildPermissions(): array
    {
        return [
            ['Parent 1', ['Child 1']],
            ['Parent 2', []],
            ['posts.view', []],
            ['posts.create', []],
            ['posts.update', []],
            ['posts.delete', []],
            ['posts.viewer', ['posts.view']],
            ['posts.redactor', ['posts.view', 'posts.create', 'posts.update']],
            ['posts.admin', ['posts.view', 'posts.create', 'posts.update', 'posts.delete']],
            [['Parent 1', 'Parent 5'], ['Child 1', 'Child 5']],
            [
                ['posts.viewer', 'posts.redactor', 'posts.admin'],
                ['posts.view', 'posts.create', 'posts.update', 'posts.delete'],
            ],
            ['non-existing', []],
        ];
    }

    /**
     * @dataProvider dataGetAllChildPermissions
     */
    public function testGetAllChildPermissions(string|array $parentNames, array $expectedChildren): void
    {
        $children = $this->getItemsStorage()->getAllChildPermissions($parentNames);
        $this->assertChildren($children, $expectedChildren);
    }

    public static function dataGetAllChildRoles(): array
    {
        return [
            ['Parent 1', []],
            ['Parent 2', ['Child 2', 'Child 3']],
            ['posts.view', []],
            ['posts.create', []],
            ['posts.update', []],
            ['posts.delete', []],
            ['posts.viewer', []],
            ['posts.redactor', ['posts.viewer']],
            ['posts.admin', ['posts.redactor', 'posts.viewer']],
            [['Parent 2', 'Parent 4'], ['Child 2', 'Child 3', 'Child 4']],
            [['posts.viewer', 'posts.redactor', 'posts.admin'], []],
            ['non-existing', []],
        ];
    }

    /**
     * @dataProvider dataGetAllChildRoles
     */
    public function testGetAllChildRoles(string|array $parentNames, array $expectedChildren): void
    {
        $children = $this->getItemsStorage()->getAllChildRoles($parentNames);
        $this->assertChildren($children, $expectedChildren);
    }

    public function testGetRoles(): void
    {
        $storage = $this->getItemsStorage();
        $roles = $storage->getRoles();

        $this->assertCount($this->initialRolesCount, $roles);
        $this->assertContainsOnlyInstancesOf(Role::class, $roles);
    }

    public static function dataGetRolesByNames(): array
    {
        return [
            [[], []],
            [['posts.viewer'], ['posts.viewer']],
            [['posts.viewer', 'posts.redactor'], ['posts.viewer', 'posts.redactor']],
            [['posts.viewer', 'posts.view'], ['posts.viewer']],
            [['posts.viewer', 'non-existing'], ['posts.viewer']],
            [['non-existing1', 'non-existing2'], []],
        ];
    }

    /**
     * @dataProvider dataGetRolesByNames
     */
    public function testGetRolesByNames(array $names, array $expectedRoleNames): void
    {
        $roles = $this->getItemsStorage()->getRolesByNames($names);

        $this->assertCount(count($expectedRoleNames), $roles);
        foreach ($roles as $roleName => $role) {
            $this->assertContains($roleName, $expectedRoleNames);
            $this->assertSame($roleName, $role->getName());
        }
    }

    public function testGetPermissions(): void
    {
        $storage = $this->getItemsStorage();
        $permissions = $storage->getPermissions();

        $this->assertCount($this->initialPermissionsCount, $permissions);
        $this->assertContainsOnlyInstancesOf(Permission::class, $permissions);
    }

    public static function dataGetPermissionsByNames(): array
    {
        return [
            [[], []],
            [['posts.view'], ['posts.view']],
            [['posts.create', 'posts.update'], ['posts.create', 'posts.update']],
            [['posts.create', 'posts.redactor'], ['posts.create']],
            [['posts.create', 'non-existing'], ['posts.create']],
            [['non-existing1', 'non-existing2'], []],
        ];
    }

    /**
     * @dataProvider dataGetPermissionsByNames
     */
    public function testGetPermissionsByNames(array $names, array $expectedPermissionNames): void
    {
        $permissions = $this->getItemsStorage()->getPermissionsByNames($names);

        $this->assertCount(count($expectedPermissionNames), $permissions);
        foreach ($permissions as $permissionName => $permission) {
            $this->assertContains($permissionName, $expectedPermissionNames);
            $this->assertSame($permissionName, $permission->getName());
        }
    }

    public static function dataRemove(): array
    {
        return [
            ['Parent 2'],
            ['non-existing'],
        ];
    }

    /**
     * @dataProvider dataRemove
     */
    public function testRemove(string $name): void
    {
        $testStorage = $this->getItemsStorageForModificationAssertions();
        $actionStorage = $this->getItemsStorage();
        $actionStorage->remove($name);

        $this->assertNull($testStorage->get($name));
        $this->assertNotEmpty($testStorage->getAll());
        $this->assertFalse($testStorage->hasChildren($name));
    }

    public static function dataGetParents(): array
    {
        return [
            ['Child 1', ['Parent 1']],
            ['Child 2', ['Parent 2']],
            ['posts.view', ['posts.admin', 'posts.redactor', 'posts.viewer']],
            ['posts.create', ['posts.admin', 'posts.redactor']],
            ['posts.update', ['posts.admin', 'posts.redactor']],
            ['posts.delete', ['posts.admin']],
            ['posts.viewer', ['posts.admin', 'posts.redactor']],
            ['posts.redactor', ['posts.admin']],
            ['posts.admin', []],
            ['non-existing', []],
        ];
    }

    /**
     * @dataProvider dataGetParents
     */
    public function testGetParents(string $childName, array $expectedParents): void
    {
        $storage = $this->getItemsStorage();
        $parents = $storage->getParents($childName);

        $this->assertCount(count($expectedParents), $parents);
        foreach ($parents as $parentName => $parent) {
            $this->assertContains($parentName, $expectedParents);
            $this->assertSame($parentName, $parent->getName());
        }
    }

    public static function dataGetAccessTree(): array
    {
        $createdAt = (new DateTime('2023-12-24 17:51:18'))->getTimestamp();
        $postsViewPermission = (new Permission('posts.view'))->withCreatedAt($createdAt)->withUpdatedAt($createdAt);
        $postsCreatePermission = (new Permission('posts.create'))->withCreatedAt($createdAt)->withUpdatedAt($createdAt);
        $postsDeletePermission = (new Permission('posts.delete'))->withCreatedAt($createdAt)->withUpdatedAt($createdAt);
        $postsViewerRole = (new Role('posts.viewer'))->withCreatedAt($createdAt)->withUpdatedAt($createdAt);
        $postsRedactorRole = (new Role('posts.redactor'))->withCreatedAt($createdAt)->withUpdatedAt($createdAt);
        $postsAdminRole = (new Role('posts.admin'))->withCreatedAt($createdAt)->withUpdatedAt($createdAt);

        return [
            [
                'posts.view',
                [
                    'posts.view' => ['item' => $postsViewPermission, 'children' => []],
                    'posts.viewer' => ['item' => $postsViewerRole, 'children' => ['posts.view' => $postsViewPermission]],
                    'posts.redactor' => [
                        'item' => $postsRedactorRole,
                        'children' => ['posts.view' => $postsViewPermission, 'posts.viewer' => $postsViewerRole],
                    ],
                    'posts.admin' => [
                        'item' => $postsAdminRole,
                        'children' => [
                            'posts.view' => $postsViewPermission,
                            'posts.viewer' => $postsViewerRole,
                            'posts.redactor' => $postsRedactorRole,
                        ],
                    ],
                ],
            ],
            [
                'posts.create',
                [
                    'posts.create' => ['item' => $postsCreatePermission, 'children' => []],
                    'posts.redactor' => [
                        'item' => $postsRedactorRole,
                        'children' => ['posts.create' => $postsCreatePermission],
                    ],
                    'posts.admin' => [
                        'item' => $postsAdminRole,
                        'children' => [
                            'posts.create' => $postsCreatePermission,
                            'posts.redactor' => $postsRedactorRole,
                        ],
                    ],
                ],
            ],
            [
                'posts.delete',
                [
                    'posts.delete' => ['item' => $postsDeletePermission, 'children' => []],
                    'posts.admin' => [
                        'item' => $postsAdminRole,
                        'children' => [
                            'posts.delete' => $postsDeletePermission,
                        ],
                    ],
                ],
            ],
            [
                'posts.viewer',
                [
                    'posts.viewer' => ['item' => $postsViewerRole, 'children' => []],
                    'posts.redactor' => [
                        'item' => $postsRedactorRole,
                        'children' => ['posts.viewer' => $postsViewerRole],
                    ],
                    'posts.admin' => [
                        'item' => $postsAdminRole,
                        'children' => [
                            'posts.viewer' => $postsViewerRole,
                            'posts.redactor' => $postsRedactorRole,
                        ],
                    ],
                ],
            ],
            ['non-existing', []],
        ];
    }

    /**
     * @dataProvider dataGetAccessTree
     */
    public function testGetAccessTree(string $name, array $expectedAccessTree): void
    {
        $this->assertEquals($expectedAccessTree, $this->getItemsStorage()->getAccessTree($name));
    }

    public function testRemoveChildren(): void
    {
        $testStorage = $this->getItemsStorageForModificationAssertions();
        $actionStorage = $this->getItemsStorage();
        $actionStorage->removeChildren('Parent 2');

        $this->assertFalse($testStorage->hasChildren('Parent 2'));
        $this->assertTrue($testStorage->hasChildren('Parent 1'));
    }

    public function testRemoveChildrenNonExisting(): void
    {
        $testStorage = $this->getItemsStorageForModificationAssertions();
        $actionStorage = $this->getItemsStorage();
        $count = count($actionStorage->getAll());
        $actionStorage->removeChildren('non-existing');

        $this->assertCount($count, $testStorage->getAll());
    }

    public function testGetRole(): void
    {
        $storage = $this->getItemsStorage();
        $role = $storage->getRole('Parent 1');

        $this->assertNotEmpty($role);
        $this->assertInstanceOf(Role::class, $role);
        $this->assertSame('Parent 1', $role->getName());
    }

    public function testAddWithCurrentTimestamps(): void
    {
        $testStorage = $this->getItemsStorageForModificationAssertions();

        $time = time();
        $newItem = (new Permission('Delete post'))->withCreatedAt($time)->withUpdatedAt($time);

        $actionStorage = $this->getItemsStorage();
        $actionStorage->add($newItem);

        $this->assertEquals(
            (new Permission('Delete post'))->withCreatedAt(1_683_707_079)->withUpdatedAt(1_683_707_079),
            $testStorage->get('Delete post'),
        );
    }

    public function testAddWithPastTimestamps(): void
    {
        $testStorage = $this->getItemsStorageForModificationAssertions();
        $time = 1_694_508_008;
        $newItem = (new Permission('Delete post'))->withCreatedAt($time)->withUpdatedAt($time);

        $actionStorage = $this->getItemsStorage();
        $actionStorage->add($newItem);

        $this->assertEquals(
            (new Permission('Delete post'))->withCreatedAt($time)->withUpdatedAt($time),
            $testStorage->get('Delete post'),
        );
    }

    public function testRemoveChild(): void
    {
        $testStorage = $this->getItemsStorageForModificationAssertions();
        $actionStorage = $this->getItemsStorage();
        $actionStorage->addChild('Parent 2', 'Child 1');
        $actionStorage->removeChild('Parent 2', 'Child 1');

        $children = $testStorage->getAllChildren('Parent 2');
        $this->assertNotEmpty($children);
        $this->assertArrayNotHasKey('Child 1', $children);

        $this->assertArrayHasKey('Child 1', $testStorage->getAllChildren('Parent 1'));
    }

    public function testRemoveChildNonExisting(): void
    {
        $testStorage = $this->getItemsStorageForModificationAssertions();
        $actionStorage = $this->getItemsStorage();
        $count = count($actionStorage->getAll());
        $actionStorage->removeChild('posts.viewer', 'non-existing');

        $this->assertSame(['posts.view'], array_keys($testStorage->getDirectChildren('posts.viewer')));
        $this->assertCount($count, $testStorage->getAll());
    }

    public function testGetAll(): void
    {
        $storage = $this->getItemsStorage();
        $this->assertCount($this->getItemsCount(), $storage->getAll());
    }

    public static function dataGetByNames(): array
    {
        return [
            [[], []],
            [['posts.viewer', 'posts.redactor'], ['posts.viewer', 'posts.redactor']],
            [['posts.create', 'posts.update'], ['posts.create', 'posts.update']],
            [['posts.viewer', 'posts.view'], ['posts.viewer', 'posts.view']],
            [['posts.viewer', 'posts.view', 'non-existing'], ['posts.viewer', 'posts.view']],
            [['non-existing1', 'non-existing2'], []],
        ];
    }

    /**
     * @dataProvider dataGetByNames
     */
    public function testGetByNames(array $names, array $expectedItemNames): void
    {
        $items = $this->getItemsStorage()->getByNames($names);

        $this->assertCount(count($expectedItemNames), $items);
        foreach ($items as $itemName => $item) {
            $this->assertContains($itemName, $expectedItemNames);
            $this->assertSame($itemName, $item->getName());
        }
    }

    public function testHasChildren(): void
    {
        $storage = $this->getItemsStorage();

        $this->assertTrue($storage->hasChildren('Parent 1'));
        $this->assertFalse($storage->hasChildren('Parent 3'));
    }

    public static function dataHasChild(): array
    {
        return [
            ['posts.viewer', 'posts.view', true],
            ['posts.viewer', 'posts.create', false],
            ['posts.viewer', 'posts.delete', false],

            ['posts.redactor', 'posts.create', true],
            ['posts.redactor', 'posts.view', true],
            ['posts.redactor', 'posts.viewer', true],
            ['posts.redactor', 'posts.delete', false],

            ['posts.admin', 'posts.delete', true],
            ['posts.admin', 'posts.create', true],
            ['posts.admin', 'posts.redactor', true],
            ['posts.admin', 'posts.view', true],
            ['posts.admin', 'posts.viewer', true],

            ['posts.viewer', 'posts.redactor', false],
            ['posts.viewer', 'posts.admin', false],
            ['posts.redactor', 'posts.admin', false],
            ['posts.viewer', 'non-existing', false],
            ['non-existing', 'posts.viewer', false],
            ['non-existing1', 'non-existing2', false],
        ];
    }

    /**
     * @dataProvider dataHasChild
     */
    public function testHasChild(string $parentName, string $childName, bool $expectedHasChild): void
    {
        $this->assertSame($expectedHasChild, $this->getItemsStorage()->hasChild($parentName, $childName));
    }

    public static function dataHasDirectChild(): array
    {
        return [
            ['posts.viewer', 'posts.view', true],
            ['posts.viewer', 'posts.create', false],
            ['posts.viewer', 'posts.delete', false],

            ['posts.redactor', 'posts.create', true],
            ['posts.redactor', 'posts.view', false],
            ['posts.redactor', 'posts.viewer', true],
            ['posts.redactor', 'posts.delete', false],

            ['posts.admin', 'posts.delete', true],
            ['posts.admin', 'posts.create', false],
            ['posts.admin', 'posts.redactor', true],
            ['posts.admin', 'posts.view', false],
            ['posts.admin', 'posts.viewer', false],

            ['posts.viewer', 'posts.redactor', false],
            ['posts.viewer', 'posts.admin', false],
            ['posts.redactor', 'posts.admin', false],
            ['posts.viewer', 'non-existing', false],
            ['non-existing', 'posts.viewer', false],
            ['non-existing1', 'non-existing2', false],
        ];
    }

    /**
     * @dataProvider dataHasDirectChild
     */
    public function testHasDirectChild(string $parentName, string $childName, bool $expectedHasDirectChild): void
    {
        $this->assertSame($expectedHasDirectChild, $this->getItemsStorage()->hasDirectChild($parentName, $childName));
    }

    public function testClearPermissions(): void
    {
        $testStorage = $this->getItemsStorageForModificationAssertions();
        $actionStorage = $this->getItemsStorage();
        $actionStorage->clearPermissions();

        $all = $testStorage->getAll();
        $this->assertNotEmpty($all);
        $this->assertContainsOnlyInstancesOf(Role::class, $all);
    }

    public function testClearRoles(): void
    {
        $testStorage = $this->getItemsStorageForModificationAssertions();
        $actionStorage = $this->getItemsStorage();
        $actionStorage->clearRoles();

        $all = $testStorage->getAll();
        $this->assertNotEmpty($all);
        $this->assertContainsOnlyInstancesOf(Permission::class, $testStorage->getAll());

        $this->assertTrue($testStorage->hasChildren('Parent 5'));
    }

    protected function getItemsStorage(): ItemsStorageInterface
    {
        if ($this->itemsStorage === null) {
            $this->itemsStorage = $this->createItemsStorage();
        }

        return $this->itemsStorage;
    }

    protected function createItemsStorage(): ItemsStorageInterface
    {
        return new FakeItemsStorage();
    }

    protected function getItemsStorageForModificationAssertions(): ItemsStorageInterface
    {
        return $this->getItemsStorage();
    }

    protected function getFixtures(): array
    {
        $itemsMap = [
            'Parent 1' => Item::TYPE_ROLE,
            'Parent 2' => Item::TYPE_ROLE,

            // Parent without children
            'Parent 3' => Item::TYPE_PERMISSION,

            'Parent 4' => Item::TYPE_PERMISSION,
            'Parent 5' => Item::TYPE_PERMISSION,

            // Parent with multiple generations of children
            'posts.admin' => Item::TYPE_ROLE,
            'posts.redactor' => Item::TYPE_ROLE,
            'posts.viewer' => Item::TYPE_ROLE,

            'Child 1' => Item::TYPE_PERMISSION,
            'Child 2' => Item::TYPE_ROLE,
            'Child 3' => Item::TYPE_ROLE,
            'Child 4' => Item::TYPE_ROLE,
            'Child 5' => Item::TYPE_PERMISSION,

            // Children of multiple generations
            'posts.view' => Item::TYPE_PERMISSION,
            'posts.create' => Item::TYPE_PERMISSION,
            'posts.update' => Item::TYPE_PERMISSION,
            'posts.delete' => Item::TYPE_PERMISSION,
        ];
        $time = time();

        $items = [];
        foreach ($itemsMap as $name => $type) {
            $items[] = [
                'name' => $name,
                'type' => $type,
                'created_at' => $time,
                'updated_at' => $time,
            ];
            $type === Item::TYPE_ROLE ? $this->initialRolesCount++ : $this->initialPermissionsCount++;
        }

        $itemsChildren = [
            // Parent: role, child: permission
            ['parent' => 'Parent 1', 'child' => 'Child 1'],
            // Parent: role, child: role
            ['parent' => 'Parent 2', 'child' => 'Child 2'],
            ['parent' => 'Parent 2', 'child' => 'Child 3'],
            // Parent: permission, child: role
            ['parent' => 'Parent 4', 'child' => 'Child 4'],
            // Parent: permission, child: permission
            ['parent' => 'Parent 5', 'child' => 'Child 5'],

            // Multiple generations of children
            ['parent' => 'posts.admin', 'child' => 'posts.redactor'],
            ['parent' => 'posts.redactor', 'child' => 'posts.viewer'],
            ['parent' => 'posts.viewer', 'child' => 'posts.view'],
            ['parent' => 'posts.redactor', 'child' => 'posts.create'],
            ['parent' => 'posts.redactor', 'child' => 'posts.update'],
            ['parent' => 'posts.admin', 'child' => 'posts.delete'],
        ];
        foreach ($itemsChildren as $itemChild) {
            $parentItemType = $itemsMap[$itemChild['parent']];
            $childItemType = $itemsMap[$itemChild['child']];

            if ($parentItemType === Item::TYPE_ROLE && $childItemType === Item::TYPE_ROLE) {
                $this->initialBothRolesChildrenCount++;
            }

            if ($parentItemType === Item::TYPE_PERMISSION && $childItemType === Item::TYPE_PERMISSION) {
                $this->initialBothPermissionsChildrenCount++;
            }

            $this->initialItemsChildrenCount++;
        }

        return ['items' => $items, 'itemsChildren' => $itemsChildren];
    }

    protected function populateItemsStorage(): void
    {
        $storage = $this->getItemsStorage();
        $fixtures = $this->getFixtures();
        foreach ($fixtures['items'] as $itemData) {
            $name = $itemData['name'];
            $item = $itemData['type'] === Item::TYPE_PERMISSION ? new Permission($name) : new Role($name);
            $item = $item
                ->withCreatedAt($itemData['created_at'])
                ->withUpdatedAt($itemData['updated_at']);
            $storage->add($item);
        }

        foreach ($fixtures['itemsChildren'] as $itemChildData) {
            $storage->addChild($itemChildData['parent'], $itemChildData['child']);
        }
    }

    private function getItemsCount(): int
    {
        return $this->initialRolesCount + $this->initialPermissionsCount;
    }

    private function assertChildren(array $children, array $expectedChildren): void
    {
        $this->assertCount(count($expectedChildren), $children);
        foreach ($children as $childName => $child) {
            $this->assertContains($childName, $expectedChildren);
            $this->assertSame($childName, $child->getName());
        }
    }
}
