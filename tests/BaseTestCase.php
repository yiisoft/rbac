<?php

namespace Yiisoft\Rbac\Tests;

use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use yii\base\Aliases;
use yii\di\Container;
use yii\di\Factory;
use yii\di\FactoryInterface;
use yii\di\Reference;
use Yiisoft\Yii\Console\Application;

class BaseTestCase extends TestCase
{
    protected static $params;
    /**
     * @var null|\yii\di\Container
     */
    protected $container;
    /**
     * @var \yii\base\Application
     */
    protected $app;
    protected $defaultAppConfig = [];

    protected function createApp()
    {
        $container = new Container([
            'container' => function (ContainerInterface $container) {
                return $container;
            },
            ContainerInterface::class => function (ContainerInterface $container) {
                return $container;
            },
            'aliases' => Aliases::class,
            FactoryInterface::class => function () {
                return new Factory([], []);
            },
            'factory' => Reference::to(FactoryInterface::class),
        ]);

        $app = new Application($container);
        $app->setAliases([
            '@runtime' => dirname(__DIR__) . DIRECTORY_SEPARATOR . 'runtime',
        ]);

        $this->app = $app;
        $this->container = $container;
    }

    /**
     * Returns a test configuration param from /data/config.php.
     *
     * @param string $name    params name
     * @param mixed  $default default value to use when param is not set.
     *
     * @return mixed  the value of the configuration param
     */
    public static function getParam($name, $default = null)
    {
        if (static::$params === null) {
            static::$params = require dirname(__DIR__) . '/config/tests.php';
        }

        return static::$params[$name] ?? $default;
    }
}
