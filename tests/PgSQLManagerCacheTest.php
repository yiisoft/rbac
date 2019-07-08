<?php
namespace Yiisoft\Rbac\Tests;

use Yiisoft\Cache\Cache;
use Yiisoft\Cache\FileCache;

/**
 * PgSQLManagerTest.
 *
 * @group db
 * @group rbac
 * @group pgsql
 */
class PgSQLManagerCacheTest extends PgSQLManagerTest
{
    protected static $driverName = 'pgsql';

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
