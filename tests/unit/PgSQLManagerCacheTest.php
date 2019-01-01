<?php
/**
 * @link http://www.yiiframework.com/
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license http://www.yiiframework.com/license/
 */

namespace yii\rbac\tests\unit;

use yii\cache\Cache;
use yii\cache\FileCache;
use yii\rbac\DbManager;
use yii\helpers\Yii;

/**
 * PgSQLManagerTest.
 * @group db
 * @group rbac
 * @group pgsql
 */
class PgSQLManagerCacheTest extends DbManagerTestCase
{
    protected static $driverName = 'pgsql';

    /**
     * @return \yii\rbac\ManagerInterface
     */
    protected function createManager()
    {
        $manager = new DbManager(
            $this->getConnection(),
            new Cache(new FileCache('@yii/tests/runtime/cache')),
            null
        );
        $manager->defaultRoles = ['myDefaultRole'];
        return $manager;
    }
}
