<?php
/**
 * @link http://www.yiiframework.com/
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license http://www.yiiframework.com/license/
 */

namespace yii\rbac\tests\unit;

use yii\rbac\DbManager;
use yii\rbac\DIRuleFactory;

/**
 * PgSQLManagerTest.
 * @group db
 * @group rbac
 * @group pgsql
 */
class PgSQLManagerTest extends DbManagerTestCase
{
    protected static $driverName = 'pgsql';

    /**
     * @return \yii\rbac\ManagerInterface
     */
    protected function createManager()
    {
        $manager = new DbManager(
            $this->getConnection(),
            $this->factory->get(DIRuleFactory::class),
            null,
            null
        );
        $manager->defaultRoles = ['myDefaultRole'];
        return $manager;        
    }      
}
