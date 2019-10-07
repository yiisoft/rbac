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

namespace Yiisoft\Rbac\Tests;

use Yiisoft\Files\FileHelper;
use Yiisoft\Rbac\ManagerInterface;
use Yiisoft\Rbac\Role;
use Yiisoft\Rbac\RuleFactory\ClassNameRuleFactory;

/**
 * @group rbac
 */
final class PhpManagerTest extends ManagerTestCase
{
    public static $filemtime;

    private $testDataPath;

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
}
