<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Exception;

use Exception;
use PHPUnit\Framework\TestCase;
use Yiisoft\Rbac\Exception\RuleNotFoundException;

final class RuleNotFoundExceptionTest extends TestCase
{
    public function testBase(): void
    {
        $exception = new RuleNotFoundException('MyRule');

        $this->assertSame('Rule "MyRule" not found.', $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }

    public function testCodeAndPreviousException(): void
    {
        $code = 212;
        $previousException = new Exception();

        $exception = new RuleNotFoundException('MyRule', $code, $previousException);

        $this->assertSame($code, $exception->getCode());
        $this->assertSame($previousException, $exception->getPrevious());
    }
}
