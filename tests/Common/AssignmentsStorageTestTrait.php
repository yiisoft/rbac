<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Common;

use Yiisoft\Rbac\Assignment;
use Yiisoft\Rbac\Item;

trait AssignmentsStorageTestTrait
{
    public function testHasItem(): void
    {
        $storage = $this->getStorage();

        $this->assertTrue($storage->hasItem('Accountant'));
    }

    public function testRenameItem(): void
    {
        $storage = $this->getStorage();
        $storage->renameItem('Accountant', 'Senior accountant');

        $this->assertTrue($storage->hasItem('Accountant'));
        $this->assertFalse($storage->hasItem('Senior accountant'));
    }

    public function testGetAll(): void
    {
        $storage = $this->getStorage();
        $all = $storage->getAll();

        $this->assertCount(2, $all);
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
}
