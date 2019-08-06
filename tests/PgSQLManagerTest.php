<?php
namespace Yiisoft\Rbac\Tests;

use Yiisoft\Rbac\DbManager;
use Yiisoft\Rbac\DIRuleFactory;

/**
 * PgSQLManagerTest.
 *
 * @group db
 * @group rbac
 * @group pgsql
 */
class PgSQLManagerTest extends DbManagerTestCase
{
    protected static $driverName = 'pgsql';

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
