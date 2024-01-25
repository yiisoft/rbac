<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Common;

use DateTime;
use SlopeIt\ClockMock\ClockMock;
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
    protected static bool $reCreateAssignmentsStorageAfterModifications = false;

    private ?ItemsStorageInterface $itemsStorage = null;
    private ?AssignmentsStorageInterface $assignmentsStorage = null;

    protected function setUp(): void
    {
        if ($this->name() === 'testAddWithCurrentTimestamp') {
            ClockMock::freeze(new DateTime('2023-05-10 08:24:39'));
        }

        $this->populateItemsStorage();
        $this->populateAssignmentsStorage();
    }

    protected function tearDown(): void
    {
        if ($this->name() === 'testAddWithCurrentTimestamp') {
            ClockMock::reset();
        }

        $this->getItemsStorage()->clear();
        $this->getAssignmentsStorage()->clear();
    }

    public function testHasItem(): void
    {
        $storage = $this->getAssignmentsStorage();

        $this->assertTrue($storage->hasItem('Accountant'));
    }

    public function testRenameItem(): void
    {
        $storage = $this->getAssignmentsStorage();
        $storage->renameItem('Accountant', 'Senior accountant');

        $storage = $this->getAssignmentsStorageForModificationAssertions();
        $this->assertFalse($storage->hasItem('Accountant'));
        $this->assertTrue($storage->hasItem('Senior accountant'));
    }

    public function testGetAll(): void
    {
        $storage = $this->getAssignmentsStorage();
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
        $storage = $this->getAssignmentsStorage();
        $storage->removeByItemName('Manager');

        $storage = $this->getAssignmentsStorageForModificationAssertions();
        $this->assertFalse($storage->hasItem('Manager'));
        $this->assertCount(2, $storage->getByUserId('jack'));
        $this->assertCount(3, $storage->getByUserId('john'));
    }

    public function testGetByUserId(): void
    {
        $storage = $this->getAssignmentsStorage();
        $assignments = $storage->getByUserId('john');

        $this->assertCount(3, $assignments);

        foreach ($assignments as $name => $assignment) {
            $this->assertSame($name, $assignment->getItemName());
        }
    }

    public static function dataGetByItemNames(): array
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
        $assignments = $this->getAssignmentsStorage()->getByItemNames($itemNames);
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
        $storage = $this->getAssignmentsStorage();
        $storage->removeByUserId('jack');

        $storage = $this->getAssignmentsStorageForModificationAssertions();
        $this->assertEmpty($storage->getByUserId('jack'));
        $this->assertNotEmpty($storage->getByUserId('john'));
    }

    public function testRemove(): void
    {
        $storage = $this->getAssignmentsStorage();
        $storage->remove('Accountant', 'john');

        $storage = $this->getAssignmentsStorageForModificationAssertions();
        $this->assertEmpty($storage->get('Accountant', 'john'));
        $this->assertNotEmpty($storage->getByUserId('john'));
    }

    public function testClear(): void
    {
        $storage = $this->getAssignmentsStorage();
        $storage->clear();

        $storage = $this->getAssignmentsStorageForModificationAssertions();
        $this->assertEmpty($storage->getAll());
    }

    public function testGet(): void
    {
        $storage = $this->getAssignmentsStorage();
        $assignment = $storage->get('Manager', 'jack');

        $this->assertNotNull($assignment);
        $this->assertSame('Manager', $assignment->getItemName());
        $this->assertSame('jack', $assignment->getUserId());
        $this->assertIsInt($assignment->getCreatedAt());
    }

    public function testGetNonExisting(): void
    {
        $this->assertNull($this->getAssignmentsStorage()->get('Researcher', 'jeff'));
    }

    public static function dataExists(): array
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
        $this->assertSame($expectedExists, $this->getAssignmentsStorage()->exists($itemName, $userId));
    }

    public static function dataUserHasItem(): array
    {
        return [
            ['user without assignments', ['Researcher', 'Accountant'], false],
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
        $this->assertSame($expectedUserHasItem, $this->getAssignmentsStorage()->userHasItem($userId, $itemNames));
    }

    public static function dataFilterUserItemNames(): array
    {
        return [
            ['john', ['Researcher', 'Accountant'], ['Researcher', 'Accountant']],
            ['jeff', ['Researcher', 'Operator'], ['Operator']],
            ['jeff', ['Researcher', 'non-existing'], []],
            ['jeff', ['non-existing', 'Operator'], ['Operator']],
            ['jeff', ['non-existing1', 'non-existing2'], []],
            ['jeff', ['Researcher', 'Accountant'], []],
        ];
    }

    /**
     * @dataProvider dataFilterUserItemNames
     */
    public function testFilterUserItemNames(string $userId, array $itemNames, array $expectedUserItemNames): void
    {
        $this->assertEqualsCanonicalizing(
            $expectedUserItemNames,
            $this->getAssignmentsStorage()->filterUserItemNames($userId, $itemNames),
        );
    }

    public function testAddWithCurrentTimestamp(): void
    {
        $storage = $this->getAssignmentsStorage();
        $storage->add(new Assignment(userId: 'john', itemName: 'Operator', createdAt: time()));

        $storage = $this->getAssignmentsStorageForModificationAssertions();
        $this->assertEquals(
            new Assignment(userId: 'john', itemName: 'Operator', createdAt: 1_683_707_079),
            $storage->get(itemName: 'Operator', userId: 'john'),
        );
    }

    public function testAddWithPastTimestamp(): void
    {
        $storage = $this->getAssignmentsStorage();
        $storage->add(new Assignment(userId: 'john', itemName: 'Operator', createdAt: 1_694_508_008));

        $storage = $this->getAssignmentsStorageForModificationAssertions();
        $this->assertEquals(
            new Assignment(userId: 'john', itemName: 'Operator', createdAt: 1_694_508_008),
            $storage->get(itemName: 'Operator', userId: 'john'),
        );
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
                $item['created_at'] = $time;
                $item['updated_at'] = $time;

                return $item;
            },
            $items,
        );
        $assignments = [
            ['item_name' => 'Researcher', 'user_id' => 'john'],
            ['item_name' => 'Accountant', 'user_id' => 'john'],
            ['item_name' => 'Quality control specialist', 'user_id' => 'john'],
            ['item_name' => 'Operator', 'user_id' => 'jack'],
            ['item_name' => 'Manager', 'user_id' => 'jack'],
            ['item_name' => 'Support specialist', 'user_id' => 'jack'],
            ['item_name' => 'Operator', 'user_id' => 'jeff'],
        ];
        $assignments = array_map(
            static function (array $item) use ($time): array {
                $item['created_at'] = $time;

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
                ->withCreatedAt($itemData['created_at'])
                ->withUpdatedAt($itemData['updated_at']);
            $this->getItemsStorage()->add($item);
        }
    }

    protected function populateAssignmentsStorage(): void
    {
        foreach ($this->getFixtures()['assignments'] as $assignmentData) {
            $this->getAssignmentsStorage()->add(
                new Assignment(
                    userId: $assignmentData['user_id'],
                    itemName: $assignmentData['item_name'],
                    createdAt: time(),
                ),
            );
        }
    }

    protected function getItemsStorage(): ItemsStorageInterface
    {
        if ($this->itemsStorage === null) {
            $this->itemsStorage = $this->createItemsStorage();
        }

        return $this->itemsStorage;
    }

    protected function getAssignmentsStorage(): AssignmentsStorageInterface
    {
        if ($this->assignmentsStorage === null) {
            $this->assignmentsStorage = $this->createAssignmentsStorage();
        }

        return $this->assignmentsStorage;
    }

    protected function createItemsStorage(): ItemsStorageInterface
    {
        return new FakeItemsStorage();
    }

    protected function createAssignmentsStorage(): AssignmentsStorageInterface
    {
        return new FakeAssignmentsStorage();
    }

    protected function getAssignmentsStorageForModificationAssertions(): AssignmentsStorageInterface
    {
        return $this->getAssignmentsStorage();
    }
}
