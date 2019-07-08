<?php
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
