<?php

namespace Yiisoft\Rbac;

/**
 * Mock for the filemtime() function for rbac classes. Avoid random test fails.
 *
 * @param string $file
 *
 * @return int
 */
function filemtime(string $file): int
{
    return \Yiisoft\Rbac\Tests\PhpManagerTest::$filemtime ?: \filemtime($file);
}

namespace Yiisoft\Rbac\Tests;

use Yiisoft\Files\FileHelper;
use Yiisoft\Rbac\Assignment;
use Yiisoft\Rbac\Exceptions\InvalidArgumentException;
use Yiisoft\Rbac\ItemInterface;
use Yiisoft\Rbac\ManagerInterface;
use Yiisoft\Rbac\Permission;
use Yiisoft\Rbac\Role;
use Yiisoft\Rbac\RuleFactory\ClassNameRuleFactory;

/**
 * @group rbac
 * @property ExposedPhpManager $auth
 */
final class PhpManagerTest extends ManagerTestCase
{
    public static ?string $filemtime;

    private string $testDataPath;

    protected function setUp(): void
    {
        static::$filemtime = null;
        $this->testDataPath = sys_get_temp_dir() . '/' . str_replace('\\', '_', get_class($this)) . uniqid('', false);
        if (FileHelper::createDirectory($this->testDataPath) === false) {
            throw new \RuntimeException('Unable to create directory: ' . $this->testDataPath);
        }

        parent::setUp();
    }

    private function getAssignmentFilePath(): string
    {
        return $this->testDataPath . '/assignments.php';
    }

    protected function tearDown(): void
    {
        FileHelper::removeDirectory($this->testDataPath);
        static::$filemtime = null;

        parent::tearDown();
    }

    protected function createManager(): ManagerInterface
    {
        return (new ExposedPhpManager(
            new ClassNameRuleFactory(),
            $this->testDataPath
        ))->setDefaultRoles(['myDefaultRole']);
    }

    public function testSaveLoad(): void
    {
        static::$time = static::$filemtime = \time();

        $this->prepareData();
        $items = $this->auth->items;
        $children = $this->auth->children;
        $assignments = $this->auth->assignments;
        $rules = $this->auth->rules;
        $this->auth->save();

        $this->auth = $this->createManager();
        $this->auth->load();

        $this->assertEquals($items, $this->auth->items);
        $this->assertEquals($children, $this->auth->children);
        $this->assertEquals($assignments, $this->auth->assignments);
        $this->assertEquals($rules, $this->auth->rules);
    }

    public function testSaveAssignments(): void
    {
        $this->auth->removeAll();

        $role = new Role('Admin');
        $this->auth->add($role);
        $this->auth->assign($role, 13);

        $this->assertStringContainsString(
            'Admin',
            file_get_contents($this->getAssignmentFilePath()),
            'Role "Admin" was not added when saving'
        );

        $role = $role->withName('NewAdmin');
        $this->auth->update('Admin', $role);
        $this->assertStringContainsString(
            'NewAdmin',
            file_get_contents($this->getAssignmentFilePath()),
            'Role "NewAdmin" was not added when saving'
        );
        $this->auth->remove($role);
        $this->assertStringNotContainsString(
            'Admin',
            file_get_contents($this->getAssignmentFilePath()),
            'Role "Admin" was not removed when saving'
        );

        $this->auth->remove($role);
        $this->assertStringNotContainsString(
            'NewAdmin',
            file_get_contents($this->getAssignmentFilePath()),
            'Role "NewAdmin" was not removed when saving'
        );
    }

    public function testReturnExceptionWhenAddingUnknownItemType(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Adding unsupported item type.');
        $this->auth->add($this->getCustomItem());
    }

    public function testRevokeAllClearAllUseAssignments(): void
    {
        $this->prepareData();
        $this->auth->revokeAll('author B');
        $this->assertEmpty($this->auth->getAssignments('author B'));
    }

    public function testReturnUserAssignment(): void
    {
        $this->prepareData();
        $this->assertInstanceOf(Assignment::class, $this->auth->getAssignment('author', 'author B'));
    }

    public function testReturnNullForUserWithoutAssignment(): void
    {
        $this->prepareData();
        $this->assertNull($this->auth->getAssignment('author', 'guest'));
    }

    public function testReturnEmptyArrayWithNoAssignments(): void
    {
        $this->prepareData();
        $this->auth->removeAllAssignments();
        $this->assertEmpty($this->auth->getAssignments('author B'));
        $this->assertEmpty($this->auth->getAssignments('author A'));
    }

    public function testReturnTrueWhenChildExists(): void
    {
        $this->prepareData();

        $reader = $this->auth->getRole('reader');
        $readPost = $this->auth->getPermission('readPost');

        $this->assertTrue($this->auth->hasChild($reader, $readPost));
    }

    public function testReturnFalseWhenHasNoChild(): void
    {
        $this->prepareData();

        $reader = $this->auth->getRole('reader');
        $updatePost = $this->auth->getPermission('updatePost');

        $this->assertFalse($this->auth->hasChild($reader, $updatePost));
    }

    public function testRemoveChildren(): void
    {
        $this->prepareData();

        $author = $this->auth->getRole('author');
        $createPost = $this->auth->getPermission('createPost');
        $updatePost = $this->auth->getPermission('updatePost');

        $this->auth->removeChildren($author);

        $this->assertFalse($this->auth->hasChild($author, $createPost));
        $this->assertFalse($this->auth->hasChild($author, $updatePost));
    }

    public function testRemoveChild(): void
    {
        $this->prepareData();

        $author = $this->auth->getRole('author');
        $createPost = $this->auth->getPermission('createPost');
        $updatePost = $this->auth->getPermission('updatePost');

        $this->auth->removeChild($author, $createPost);

        $this->assertFalse($this->auth->hasChild($author, $createPost));
        $this->assertTrue($this->auth->hasChild($author, $updatePost));
    }

    public function testRuleSetWhenUpdatingItem(): void
    {
        $newRule = new EasyRule();

        $permissionName = 'newPermission';
        $permission = (new Permission($permissionName))
            ->withRuleName($newRule->getName());

        $this->auth->update($permissionName, $permission);
        $this->assertNotNull($this->auth->getPermission($permissionName));
        $this->assertNotNull($this->auth->getRule($newRule->getName()));
    }

    public function testReturnExceptionWhenUpdateWithUnknownItemType(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Updating unsupported item type.');
        $customItem = $this->getCustomItem();
        $this->auth->update($customItem->getName(), $customItem);
    }

    public function testDefaultRolesSetWithClosure(): void
    {
        $this->auth->setDefaultRoles(
            static function () {
                return ['newDefaultRole'];
            }
        );

        $this->assertEquals($this->auth->getDefaultRoles(), ['newDefaultRole']);
    }

    public function testReturnFalseForNonExistingUserAndNoDefaultRoles(): void
    {
        $this->auth->setDefaultRoles([]);
        $this->assertFalse($this->auth->userHasPermission('unknown user', 'createPost'));
    }

    public function testReturnExceptionWhenRemoveByUnknownItemType(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Removing unsupported item type.');
        $this->auth->remove($this->getCustomItem());
    }

    public function testRuleSetWhenAddingItem(): void
    {
        $newRule = new EasyRule();
        $itemName = 'newPermission';
        $item = (new Permission($itemName))
            ->withRuleName($newRule->getName());

        $this->auth->add($item);
        $this->assertNotNull($this->auth->getPermission($itemName));
        $this->assertNotNull($this->auth->getRule($newRule->getName()));
    }

    public function testGetRuleReturnNullForNonExistingRole(): void
    {
        $this->prepareData();
        $author = $this->auth->getRole('createPost');

        $this->assertNull($author);
    }

    private function getCustomItem(): ItemInterface
    {
        return new class() implements ItemInterface {
            public function getName(): string
            {
                return 'custom item';
            }

            public function getAttributes(): array
            {
                return [
                    'name' => $this->getName()
                ];
            }
        };
    }
}
