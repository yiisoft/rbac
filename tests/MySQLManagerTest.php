<?php
/**
 * @link http://www.yiiframework.com/
 *
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license http://www.yiiframework.com/license/
 */

namespace Yiisoft\Rbac\Tests;

use Yiisoft\Rbac\DbManager;
use Yiisoft\Rbac\DIRuleFactory;

/**
 * MySQLManagerTest.
 *
 * @group db
 * @group rbac
 * @group mysql
 */
class MySQLManagerTest extends DbManagerTestCase
{
    protected static $driverName = 'mysql';

    /**
     * @return \Yiisoft\Rbac\ManagerInterface
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
