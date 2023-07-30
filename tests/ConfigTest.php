<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use PHPUnit\Framework\TestCase;
use Yiisoft\Di\Container;
use Yiisoft\Di\ContainerConfig;
use Yiisoft\Rbac\AssignmentsStorageInterface;
use Yiisoft\Rbac\ItemsStorageInterface;
use Yiisoft\Rbac\Manager;
use Yiisoft\Rbac\ManagerInterface;
use Yiisoft\Rbac\RuleFactoryInterface;
use Yiisoft\Rbac\Tests\Support\FakeAssignmentsStorage;
use Yiisoft\Rbac\Tests\Support\FakeItemsStorage;
use Yiisoft\Rbac\Tests\Support\SimpleRuleFactory;

final class ConfigTest extends TestCase
{
    public function testBase(): void
    {
        $container = $this->createTestContainer();

        $manager = $container->get(ManagerInterface::class);
        $this->assertInstanceOf(Manager::class, $manager);
    }

    private function createTestContainer(array|null $params = null): Container
    {
        $definitions = $this->getContainerDefinitions($params);
        $definitions = array_merge($definitions, [
            ItemsStorageInterface::class => FakeItemsStorage::class,
            AssignmentsStorageInterface::class => FakeAssignmentsStorage::class,
            RuleFactoryInterface::class => SimpleRuleFactory::class,
        ]);
        $config = ContainerConfig::create()->withDefinitions($definitions);

        return new Container($config);
    }

    private function getContainerDefinitions(array|null $params): array
    {
        if ($params === null) {
            $params = $this->getParams();
        }

        return require dirname(__DIR__) . '/config/di.php';
    }

    private function getParams(): array
    {
        return require dirname(__DIR__) . '/config/params.php';
    }
}
