<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Exception;

use Exception;
use PHPUnit\Framework\TestCase;
use Yiisoft\Rbac\Exception\ItemAlreadyExistsException;
use Yiisoft\Rbac\Role;

final class ItemAlreadyExistsExceptionTest extends TestCase
{
    public function testBase(): void
    {
        $exception = new ItemAlreadyExistsException(new Role('reader'));

        $this->assertSame('Role or permission with name "reader" already exists.', $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }

    public function testCodeAndPreviousException(): void
    {
        $code = 212;
        $previousException = new Exception();

        $exception = new ItemAlreadyExistsException(new Role('reader'), $code, $previousException);

        $this->assertSame($code, $exception->getCode());
        $this->assertSame($previousException, $exception->getPrevious());
    }
}
