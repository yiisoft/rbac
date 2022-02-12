<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Exception;

use Exception;
use PHPUnit\Framework\TestCase;
use Yiisoft\Rbac\Exception\RuleInterfaceNotImplementedException;
use Yiisoft\Rbac\RuleInterface;

final class RuleInterfaceNotImplementedExceptionTest extends TestCase
{
    public function testMessage(): void
    {
        $exception = new RuleInterfaceNotImplementedException('MyRule');

        $this->assertSame(
            'Rule "MyRule" should implement "' . RuleInterface::class . '".',
            $exception->getMessage()
        );
    }

    public function testCodeAndPreviousException(): void
    {
        $code = 212;
        $previousException = new Exception();

        $exception = new RuleInterfaceNotImplementedException('MyRule', $code, $previousException);

        $this->assertSame($code, $exception->getCode());
        $this->assertSame($previousException, $exception->getPrevious());
    }
}
