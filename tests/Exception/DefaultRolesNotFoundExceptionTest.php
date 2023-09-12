<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Exception;

use PHPUnit\Framework\TestCase;
use Yiisoft\Rbac\Exception\DefaultRolesNotFoundException;

final class DefaultRolesNotFoundExceptionTest extends TestCase
{
    public function testGetCode(): void
    {
        $exception = new DefaultRolesNotFoundException('test');
        $this->assertSame(0, $exception->getCode());
    }

    public function testReturnTypes(): void
    {
        $exception = new DefaultRolesNotFoundException('test');
        $this->assertIsString($exception->getName());
        $this->assertIsString($exception->getSolution());
    }
}
