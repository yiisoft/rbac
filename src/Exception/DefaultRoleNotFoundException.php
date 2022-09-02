<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Exception;

use RuntimeException;
use Yiisoft\FriendlyException\FriendlyExceptionInterface;

class DefaultRoleNotFoundException extends RuntimeException implements FriendlyExceptionInterface
{
    public function getName(): string
    {
        return 'Default role not found.';
    }

    public function getSolution(): ?string
    {
        return <<<'SOLUTION'
            You have to add default roles before using it as default.
            SOLUTION;
    }
}
