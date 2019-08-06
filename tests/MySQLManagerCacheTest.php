<?php
namespace Yiisoft\Rbac\Tests;

use Yiisoft\Cache\Cache;
use Yiisoft\Cache\FileCache;

/**
 * MySQLManagerCacheTest.
 *
 * @group rbac
 * @group db
 * @group mysql
 */
class MySQLManagerCacheTest extends MySQLManagerTest
{
    /**
     * @return \Yiisoft\Rbac\ManagerInterface
     */
    protected function createManager()
    {
        $manager = parent::createManager();
        $manager->cache = new Cache(new FileCache('@yii/tests/runtime/cache'));

        return $manager;
    }
}
