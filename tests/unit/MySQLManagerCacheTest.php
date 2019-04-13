<?php
/**
 * @link http://www.yiiframework.com/
 *
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license http://www.yiiframework.com/license/
 */

namespace yii\rbac\tests\unit;

use yii\cache\Cache;
use yii\cache\FileCache;

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
     * @return \yii\rbac\ManagerInterface
     */
    protected function createManager()
    {
        $manager = parent::createManager();
        $manager->cache = new Cache(new FileCache('@yii/tests/runtime/cache'));

        return $manager;
    }
}
