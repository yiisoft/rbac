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
 * MySQLManagerTest.
 * @group db
 * @group rbac
 * @group mysql
 */
class MySQLManagerTest extends DbManagerTestCase
{
    protected static $driverName = 'mysql';

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
