<?php
/**
 * @link http://www.yiiframework.com/
 *
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license http://www.yiiframework.com/license/
 */

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

use yii\helpers\FileHelper;
use Yiisoft\Rbac\DIRuleFactory;

/**
 * @group rbac
 *
 * @property ExposedPhpManager $auth
 */
class PhpManagerTest extends ManagerTestCase
{
    public static $filemtime;
    public static $time;

    protected function getItemFile()
    {
        return $this->app->getRuntimePath().'/rbac-items.php';
    }

    protected function getAssignmentFile()
    {
        return $this->app->getRuntimePath().'/rbac-assignments.php';
    }

    protected function getRuleFile()
    {
        return $this->app->getRuntimePath().'/rbac-rules.php';
    }

    protected function removeDataFiles()
    {
        @unlink($this->getItemFile());
        @unlink($this->getAssignmentFile());
        @unlink($this->getRuleFile());
    }

    /**
     * {@inheritdoc}
     */
    protected function createManager()
    {
        return (new ExposedPhpManager(
            '',
            $this->factory->get(DIRuleFactory::class),
            $this->getItemFile(),
            $this->getAssignmentFile(),
            $this->getRuleFile()
        ))->setDefaultRoles(['myDefaultRole']);
    }

    protected function setUp()
    {
        static::$filemtime = null;
        static::$time = null;
        parent::setUp();

        $this->mockApplication();
        FileHelper::createDirectory($this->app->getAlias('@runtime'));
        $this->removeDataFiles();
        $this->auth = $this->createManager();
    }

    protected function tearDown()
    {
        $this->removeDataFiles();
        static::$filemtime = null;
        static::$time = null;
        parent::tearDown();
    }

    public function testSaveLoad()
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

    public function testUpdateItemName()
    {
        $this->prepareData();

        $name = 'readPost';
        $permission = $this->auth->getPermission($name);
        $permission->name = 'UPDATED-NAME';
        $this->assertTrue($this->auth->update($name, $permission), 'You should be able to update name.');
    }

    public function testUpdateDescription()
    {
        $this->prepareData();
        $name = 'readPost';
        $permission = $this->auth->getPermission($name);
        $permission->description = 'UPDATED-DESCRIPTION';
        $this->assertTrue($this->auth->update($name, $permission), 'You should be able to save w/o changing name.');
    }

    /**
     * @expectedException \Yiisoft\Rbac\Exceptions\InvalidArgumentException
     */
    public function testOverwriteName()
    {
        $this->prepareData();
        $name = 'readPost';
        $permission = $this->auth->getPermission($name);
        $permission->name = 'createPost';
        $this->auth->update($name, $permission);
    }

    public function testSaveAssignments()
    {
        $this->auth->removeAll();
        $role = $this->auth->createRole('Admin');
        $this->auth->add($role);
        $this->auth->assign($role, 13);
        $this->assertContains('Admin', file_get_contents($this->getAssignmentFile()));
        $role->name = 'NewAdmin';
        $this->auth->update('Admin', $role);
        $this->assertContains('NewAdmin', file_get_contents($this->getAssignmentFile()));
        $this->auth->remove($role);
        $this->assertNotContains('NewAdmin', file_get_contents($this->getAssignmentFile()));
    }
}
