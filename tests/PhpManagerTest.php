<?php
namespace Yiisoft\Rbac;

/**
 * Mock for the filemtime() function for rbac classes. Avoid random test fails.
 *
 * @param string $file
 *
 * @return int
 */
function filemtime($file)
{
    return \Yiisoft\Rbac\Tests\PhpManagerTest::$filemtime ?: \filemtime($file);
}

/**
 * Mock for the time() function for rbac classes. Avoid random test fails.
 *
 * @return int
 */
function time()
{
    return \Yiisoft\Rbac\Tests\PhpManagerTest::$time ?: \time();
}

namespace Yiisoft\Rbac\Tests;

use Yiisoft\Files\FileHelper;
use Yiisoft\Rbac\DIRuleFactory;

/**
 * @group rbac
 */
final class PhpManagerTest extends ManagerTestCase
{
    public static $filemtime;
    public static $time;

    private $testDataPath = '';

    protected function setUp()
    {
        static::$filemtime = null;
        static::$time = null;
        parent::setUp();

        $this->testDataPath = sys_get_temp_dir() . '/' . str_replace('\\', '_', get_class($this)) . uniqid('', false);
    }

    protected function tearDown()
    {
        FileHelper::removeDirectory($this->testDataPath);
        static::$filemtime = null;
        static::$time = null;
        parent::tearDown();
    }

    protected function createManager()
    {
        return (new ExposedPhpManager(
            '',
            $this->container->get(DIRuleFactory::class)
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

    public function testUpdateItemName(): void
    {
        $this->prepareData();

        $name = 'readPost';
        $permission = $this->auth->getPermission($name);
        $permission->name = 'UPDATED-NAME';
        $this->auth->update($name, $permission);
        $oldPermission = $this->auth->getPermission('readPost');
        $newPermission = $this->auth->getPermission('UPDATED-NAME');
        $this->assertNull($oldPermission);
        $this->assertNotNull($newPermission);
    }

    public function testUpdateDescription(): void
    {
        $this->prepareData();
        $name = 'readPost';
        $permission = $this->auth->getPermission($name);
        $newDescription = 'UPDATED-DESCRIPTION';
        $permission->description = $newDescription;
        $this->auth->update($name, $permission);

        $permission = $this->auth->getPermission('readPost');
        $this->assertEquals($newDescription, $permission->description);
    }

    public function testOverwriteName(): void
    {
        $this->prepareData();
        $name = 'readPost';
        $permission = $this->auth->getPermission($name);
        $permission->name = 'createPost';
        $this->expectException(\Yiisoft\Rbac\Exceptions\InvalidArgumentException::class);
        $this->auth->update($name, $permission);
    }

    public function testSaveAssignments(): void
    {
        $this->auth->removeAll();
        $role = $this->auth->createRole('Admin');
        $this->auth->add($role);
        $this->auth->assign($role, 13);
        $this->assertContains('Admin', file_get_contents($this->getAssignmentFilePath()));
        $role->name = 'NewAdmin';
        $this->auth->update('Admin', $role);
        $this->assertContains('NewAdmin', file_get_contents($this->getAssignmentFilePath()));
        $this->auth->remove($role);
        $this->assertNotContains('NewAdmin', file_get_contents($this->getAssignmentFilePath()));
    }
}
