<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Common;

use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\Role;

trait ItemsStorageTestTrait
{
    private int $initialRolesCount = 0;
    private int $initialPermissionsCount = 0;
    private int $initialBothRolesChildrenCount = 0;
    private int $initialBothPermissionsChildrenCount = 0;
    private int $initialItemsChildrenCount = 0;

    public function dataUpdate(): array
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
        $storage = $this->getStorage();

        $item = $storage->get($itemName);
        $this->assertNull($item->getRuleName());

        $item = $item
            ->withName('Super Admin')
            ->withRuleName('super admin');
        $storage->update($itemName, $item);

        $this->assertNull($storage->get($itemName));

        $item = $storage->get('Super Admin');
        $this->assertNotNull($item);

        $this->assertSame('Super Admin', $item->getName());
        $this->assertSame('super admin', $item->getRuleName());

        $this->assertSame($expectedHasChildren, $storage->hasChildren($parentNameForChildrenCheck));
    }

    public function testGet(): void
    {
        $storage = $this->getStorage();
        $item = $storage->get('Parent 3');

        $this->assertInstanceOf(Permission::class, $item);
        $this->assertSame(Item::TYPE_PERMISSION, $item->getType());
        $this->assertSame('Parent 3', $item->getName());
    }

    public function testGetWithNonExistingName(): void
    {
        $storage = $this->getStorage();
        $this->assertNull($storage->get('Non-existing name'));
    }

    public function existsProvider(): array
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
     * @dataProvider existsProvider
     */
    public function testExists(string $name, bool $exists): void
    {
        $storage = $this->getStorage();
        $this->assertSame($storage->exists($name), $exists);
    }

    public function testGetPermission(): void
    {
        $storage = $this->getStorage();
        $permission = $storage->getPermission('Child 1');

        $this->assertInstanceOf(Permission::class, $permission);
        $this->assertSame('Child 1', $permission->getName());
    }

    public function testAddChild(): void
    {
        $storage = $this->getStorage();
        $storage->addChild('Parent 2', 'Child 1');

        $children = $storage->getAllChildren('Parent 2');
        $this->assertCount(3, $children);

        foreach ($children as $name => $item) {
            $this->assertSame($name, $item->getName());
        }
    }

    public function testClear(): void
    {
        $storage = $this->getStorage();
        $storage->clear();

        $this->assertEmpty($storage->getAll());
    }

    public function dataGetDirectChildren(): array
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
        ];
    }

    /**
     * @dataProvider dataGetDirectChildren
     */
    public function testGetDirectChildren(string $parentName, array $expectedChildren): void
    {
        $children = $this->getStorage()->getDirectChildren($parentName);
        $this->assertChildren($children, $expectedChildren);
    }

    public function dataGetAllChildren(): array
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
        ];
    }

    /**
     * @dataProvider dataGetAllChildren
     */
    public function testGetAllChildren(string $parentName, array $expectedChildren): void
    {
        $children = $this->getStorage()->getAllChildren($parentName);
        $this->assertChildren($children, $expectedChildren);
    }

    public function dataGetAllChildPermissions(): array
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
        ];
    }

    /**
     * @dataProvider dataGetAllChildPermissions
     */
    public function testGetAllChildPermissions(string $parentName, array $expectedChildren): void
    {
        $children = $this->getStorage()->getAllChildPermissions($parentName);
        $this->assertChildren($children, $expectedChildren);
    }

    public function dataGetAllChildRoles(): array
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
        ];
    }

    /**
     * @dataProvider dataGetAllChildRoles
     */
    public function testGetAllChildRoles(string $parentName, array $expectedChildren): void
    {
        $children = $this->getStorage()->getAllChildRoles($parentName);
        $this->assertChildren($children, $expectedChildren);
    }

    public function testGetRoles(): void
    {
        $storage = $this->getStorage();
        $roles = $storage->getRoles();

        $this->assertCount($this->initialRolesCount, $roles);
        $this->assertContainsOnlyInstancesOf(Role::class, $roles);
    }

    public function testGetPermissions(): void
    {
        $storage = $this->getStorage();
        $permissions = $storage->getPermissions();

        $this->assertCount($this->initialPermissionsCount, $permissions);
        $this->assertContainsOnlyInstancesOf(Permission::class, $permissions);
    }

    public function testRemove(): void
    {
        $storage = $this->getStorage();
        $storage->remove('Parent 2');

        $this->assertNull($storage->get('Parent 2'));
        $this->assertNotEmpty($storage->getAll());
        $this->assertFalse($storage->hasChildren('Parent 2'));
    }

    public function getParentsProvider(): array
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
        ];
    }

    /**
     * @dataProvider getParentsProvider
     */
    public function testGetParents(string $childName, array $expectedParents): void
    {
        $storage = $this->getStorage();
        $parents = $storage->getParents($childName);

        $this->assertCount(count($expectedParents), $parents);
        foreach ($parents as $parentName => $parent) {
            $this->assertContains($parentName, $expectedParents);
            $this->assertSame($parentName, $parent->getName());
        }
    }

    public function testRemoveChildren(): void
    {
        $storage = $this->getStorage();
        $storage->removeChildren('Parent 2');

        $this->assertFalse($storage->hasChildren('Parent 2'));
        $this->assertTrue($storage->hasChildren('Parent 1'));
    }

    public function testGetRole(): void
    {
        $storage = $this->getStorage();
        $role = $storage->getRole('Parent 1');

        $this->assertNotEmpty($role);
        $this->assertInstanceOf(Role::class, $role);
        $this->assertSame('Parent 1', $role->getName());
    }

    public function testAdd(): void
    {
        $storage = $this->getStorage();
        $newItem = new Permission('Delete post');
        $storage->add($newItem);

        $this->assertInstanceOf(Permission::class, $storage->get('Delete post'));
    }

    public function testRemoveChild(): void
    {
        $storage = $this->getStorage();
        $storage->addChild('Parent 2', 'Child 1');
        $storage->removeChild('Parent 2', 'Child 1');

        $children = $storage->getAllChildren('Parent 2');
        $this->assertNotEmpty($children);
        $this->assertArrayNotHasKey('Child 1', $children);

        $this->assertArrayHasKey('Child 1', $storage->getAllChildren('Parent 1'));
    }

    public function testGetAll(): void
    {
        $storage = $this->getStorage();
        $this->assertCount($this->getItemsCount(), $storage->getAll());
    }

    public function testHasChildren(): void
    {
        $storage = $this->getStorage();

        $this->assertTrue($storage->hasChildren('Parent 1'));
        $this->assertFalse($storage->hasChildren('Parent 3'));
    }

    public function dataHasChild(): array
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
        ];
    }

    /**
     * @dataProvider dataHasChild
     */
    public function testHasChild(string $parentName, string $childName, bool $expectedHasChild): void
    {
        $this->assertSame($expectedHasChild, $this->getStorage()->hasChild($parentName, $childName));
    }

    public function dataHasDirectChild(): array
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
        ];
    }

    /**
     * @dataProvider dataHasDirectChild
     */
    public function testHasDirectChild(string $parentName, string $childName, bool $expectedHasDirectChild): void
    {
        $this->assertSame($expectedHasDirectChild, $this->getStorage()->hasDirectChild($parentName, $childName));
    }

    public function testClearPermissions(): void
    {
        $storage = $this->getStorage();
        $storage->clearPermissions();

        $all = $storage->getAll();
        $this->assertNotEmpty($all);
        $this->assertContainsOnlyInstancesOf(Role::class, $all);
    }

    public function testClearRoles(): void
    {
        $storage = $this->getStorage();
        $storage->clearRoles();

        $all = $storage->getAll();
        $this->assertNotEmpty($all);
        $this->assertContainsOnlyInstancesOf(Permission::class, $storage->getAll());

        $this->assertTrue($storage->hasChildren('Parent 5'));
    }

    protected function getFixtures(): array
    {
        $time = time();
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

        $items = [];
        foreach ($itemsMap as $name => $type) {
            $items[] = [
                'name' => $name,
                'type' => $type,
                'createdAt' => $time,
                'updatedAt' => $time,
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
            ['parent' => 'posts.viewer', 'child' => 'posts.view'],
            ['parent' => 'posts.redactor', 'child' => 'posts.create'],
            ['parent' => 'posts.redactor', 'child' => 'posts.update'],
            ['parent' => 'posts.admin', 'child' => 'posts.delete'],
            ['parent' => 'posts.admin', 'child' => 'posts.redactor'],
            ['parent' => 'posts.redactor', 'child' => 'posts.viewer'],
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
