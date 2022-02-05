<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

use Psr\Container\ContainerInterface;
use Yiisoft\Factory\Factory;
use Yiisoft\Factory\NotFoundException;
use Yiisoft\Rbac\Exception\RuleInterfaceNotImplementedException;
use Yiisoft\Rbac\Exception\RuleNotFoundException;

use function array_key_exists;

final class RuleContainer implements RuleContainerInterface
{
    private Factory $factory;

    /**
     * @var RuleInterface[]
     * @psalm-var array<string,RuleInterface>
     */
    private array $instances = [];

    /**
     * @psalm-param array<string, mixed> $definitions
     */
    public function __construct(ContainerInterface $container, array $definitions, bool $validate = true)
    {
        $this->factory = new Factory($container, $definitions, $validate);
    }

    public function get(string $name): RuleInterface
    {
        if (!array_key_exists($name, $this->instances)) {
            try {
                $rule = $this->factory->create($name);
            } catch (NotFoundException $e) {
                throw new RuleNotFoundException($name, 0, $e);
            }

            if (!$rule instanceof RuleInterface) {
                throw new RuleInterfaceNotImplementedException($name);
            }

            $this->instances[$name] = $rule;
        }

        return $this->instances[$name];
    }
}
