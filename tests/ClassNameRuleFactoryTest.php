<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use stdClass;
use Yiisoft\Rbac\ClassNameRuleFactory;
use Yiisoft\Rbac\RuleInterface;
use Yiisoft\Rbac\Tests\Support\AllowRule;
use Yiisoft\Rbac\Tests\Support\RuleWithRequiredName;

final class ClassNameRuleFactoryTest extends TestCase
{
    public function testBase(): void
    {
        $factory = new ClassNameRuleFactory();

        $rule = $factory->create(AllowRule::class);

        $this->assertInstanceOf(AllowRule::class, $rule);
    }

    public function dataRuntimeException(): array
    {
        return [
            [
                ClassNameRuleFactory::class . ' supports creating rules by class name only, "non-exists-class" given.',
                'non-exists-class',
            ],
            [
                'Can not instantiate rule "' . RuleWithRequiredName::class . '".',
                RuleWithRequiredName::class,
            ],
            [
                'Rule "' . stdClass::class . '" must be an instance of ' . RuleInterface::class . '.',
                stdClass::class,
            ],
        ];
    }

    /**
     * @dataProvider dataRuntimeException
     */
    public function testRuntimeException(string $expectedMessage, string $name): void
    {
        $factory = new ClassNameRuleFactory();

        $this->expectException(RuntimeException::class);
        $this->expectErrorMessage($expectedMessage);
        $factory->create($name);
    }
}
