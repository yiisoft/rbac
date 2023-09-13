<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Common;

use Yiisoft\Rbac\Assignment;
use Yiisoft\Rbac\AssignmentsStorageInterface;
use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\ItemsStorageInterface;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\Role;
use Yiisoft\Rbac\Tests\Support\FakeAssignmentsStorage;
use Yiisoft\Rbac\Tests\Support\FakeItemsStorage;

trait AssignmentsStorageTestTrait
{
    private ?ItemsStorageInterface $itemsStorage = null;
    private ?AssignmentsStorageInterface $storage = null;

    protected function setUp(): void
    {
        $this->populateItemsStorage();
        $this->populateStorage();
    }

    protected function tearDown(): void
    {
        $this->getItemsStorage()->clear();
        $this->getStorage()->clear();
    }

    public function testHasItem(): void
    {
        $storage = $this->getStorage();

        $this->assertTrue($storage->hasItem('Accountant'));
    }

    public function testRenameItem(): void
    {
        $storage = $this->getStorage();
        $storage->renameItem('Accountant', 'Senior accountant');

        $this->assertFalse($storage->hasItem('Accountant'));
        $this->assertTrue($storage->hasItem('Senior accountant'));
    }

    public function testGetAll(): void
    {
        $storage = $this->getStorage();
        $all = $storage->getAll();

        $this->assertCount(3, $all);
        foreach ($all as $userId => $assignments) {
            foreach ($assignments as $name => $assignment) {
                $this->assertSame($userId, $assignment->getUserId());
                $this->assertSame($name, $assignment->getItemName());
            }
        }
    }

    public function testRemoveByItemName(): void
    {
        $storage = $this->getStorage();
        $storage->removeByItemName('Manager');

        $this->assertFalse($storage->hasItem('Manager'));
        $this->assertCount(2, $storage->getByUserId('jack'));
        $this->assertCount(3, $storage->getByUserId('john'));
    }

    public function testGetByUserId(): void
    {
        $storage = $this->getStorage();
        $assignments = $storage->getByUserId('john');

        $this->assertCount(3, $assignments);

        foreach ($assignments as $name => $assignment) {
            $this->assertSame($name, $assignment->getItemName());
        }
    }

    public function dataGetByItemNames(): array
    {
        return [
            [[], []],
            [['Researcher'], [['Researcher', 'john']]],
            [['Researcher', 'Operator'], [['Researcher', 'john'], ['Operator', 'jack'], ['Operator', 'jeff']]],
            [['Researcher', 'jack'], [['Researcher', 'john']]],
            [['Researcher', 'non-existing'], [['Researcher', 'john']]],
            [['non-existing1', 'non-existing2'], []],
        ];
    }

    /**
     * @dataProvider dataGetByItemNames
     */
    public function testGetByItemNames(array $itemNames, array $expectedAssignments): void
    {
        $assignments = $this->getStorage()->getByItemNames($itemNames);
        $this->assertCount(count($expectedAssignments), $assignments);

        $assignmentFound = false;
        foreach ($assignments as $assignment) {
            foreach ($expectedAssignments as $expectedAssignment) {
                if (
                    $assignment->getItemName() === $expectedAssignment[0] &&
                    $assignment->getUserId() === $expectedAssignment[1]
                ) {
                    $assignmentFound = true;
                }
            }
        }

        if (!empty($expectedAssignments) && !$assignmentFound) {
            $this->fail('Assignment not found.');
        }
    }

    public function testRemoveByUserId(): void
    {
        $storage = $this->getStorage();
        $storage->removeByUserId('jack');

        $this->assertEmpty($storage->getByUserId('jack'));
        $this->assertNotEmpty($storage->getByUserId('john'));
    }

    public function testRemove(): void
    {
        $storage = $this->getStorage();
        $storage->remove('Accountant', 'john');

        $this->assertEmpty($storage->get('Accountant', 'john'));
        $this->assertNotEmpty($storage->getByUserId('john'));
    }

    public function testClear(): void
    {
        $storage = $this->getStorage();
        $storage->clear();

        $this->assertEmpty($storage->getAll());
    }

    public function testGet(): void
    {
        $storage = $this->getStorage();
        $assignment = $storage->get('Manager', 'jack');

        $this->assertSame('Manager', $assignment->getItemName());
        $this->assertSame('jack', $assignment->getUserId());
        $this->assertIsInt($assignment->getCreatedAt());
    }

    public function testGetNonExisting(): void
    {
        $this->assertNull($this->getStorage()->get('Researcher', 'jeff'));
    }

    public function dataExists(): array
    {
        return [
            ['Manager', 'jack', true],
            ['jack', 'Manager', false],
            ['Manager', 'non-existing', false],
            ['non-existing', 'jack', false],
            ['non-existing1', 'non-existing2', false],
        ];
    }

    /**
     * @dataProvider dataExists
     */
    public function testExists(string $itemName, string $userId, bool $expectedExists): void
    {
        $this->assertSame($expectedExists, $this->getStorage()->exists($itemName, $userId));
    }

    public function dataUserHasItem(): array
    {
        return [
            ['john', ['Researcher', 'Accountant'], true],
            ['jeff', ['Researcher', 'Operator'], true],
            ['jeff', ['Researcher', 'non-existing'], false],
            ['jeff', ['non-existing', 'Operator'], true],
            ['jeff', ['non-existing1', 'non-existing2'], false],
            ['jeff', ['Researcher', 'Accountant'], false],
        ];
    }

    /**
     * @dataProvider dataUserHasItem
     */
    public function testUserHasItem(string $userId, array $itemNames, bool $expectedUserHasItem): void
    {
        $this->assertSame($expectedUserHasItem, $this->getStorage()->userHasItem($userId, $itemNames));
    }

    public function testAdd(): void
    {
        $storage = $this->getStorage();
        $storage->add('Operator', 'john');

        $this->assertInstanceOf(Assignment::class, $storage->get('Operator', 'john'));
    }

    protected function getFixtures(): array
    {
        $time = time();
        $items = [
            ['name' => 'Researcher', 'type' => Item::TYPE_ROLE],
            ['name' => 'Accountant', 'type' => Item::TYPE_ROLE],
            ['name' => 'Quality control specialist', 'type' => Item::TYPE_ROLE],
            ['name' => 'Operator', 'type' => Item::TYPE_ROLE],
            ['name' => 'Manager', 'type' => Item::TYPE_ROLE],
            ['name' => 'Support specialist', 'type' => Item::TYPE_ROLE],
            ['name' => 'Delete user', 'type' => Item::TYPE_PERMISSION],
        ];
        $items = array_map(
            static function (array $item) use ($time): array {
                $item['createdAt'] = $time;
                $item['updatedAt'] = $time;

                return $item;
            },
            $items,
        );
        $assignments = [
            ['itemName' => 'Researcher', 'userId' => 'john'],
            ['itemName' => 'Accountant', 'userId' => 'john'],
            ['itemName' => 'Quality control specialist', 'userId' => 'john'],
            ['itemName' => 'Operator', 'userId' => 'jack'],
            ['itemName' => 'Manager', 'userId' => 'jack'],
            ['itemName' => 'Support specialist', 'userId' => 'jack'],
            ['itemName' => 'Operator', 'userId' => 'jeff'],
        ];
        $assignments = array_map(
            static function (array $item) use ($time): array {
                $item['createdAt'] = $time;

                return $item;
            },
            $assignments,
        );

        return ['items' => $items, 'assignments' => $assignments];
    }

    protected function populateItemsStorage(): void
    {
        foreach ($this->getFixtures()['items'] as $itemData) {
            $name = $itemData['name'];
            $item = $itemData['type'] === Item::TYPE_PERMISSION ? new Permission($name) : new Role($name);
            $item = $item
                ->withCreatedAt($itemData['createdAt'])
                ->withUpdatedAt($itemData['updatedAt']);
            $this->getItemsStorage()->add($item);
        }
    }

    protected function populateStorage(): void
    {
        foreach ($this->getFixtures()['assignments'] as $assignmentData) {
            $this->getStorage()->add($assignmentData['itemName'], $assignmentData['userId']);
        }
    }

    protected function getItemsStorage(): ItemsStorageInterface
    {
        if ($this->itemsStorage === null) {
            $this->itemsStorage = $this->createItemsStorage();
        }

        return $this->itemsStorage;
    }

    protected function getStorage(): AssignmentsStorageInterface
    {
        if ($this->storage === null) {
            $this->storage = $this->createStorage();
        }

        return $this->storage;
    }

    protected function createItemsStorage(): ItemsStorageInterface
    {
        return new FakeItemsStorage();
    }

    protected function createStorage(): AssignmentsStorageInterface
    {
        return new FakeAssignmentsStorage();
    }
}
