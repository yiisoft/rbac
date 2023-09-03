<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Exception;

use RuntimeException;
use Yiisoft\FriendlyException\FriendlyExceptionInterface;

class DefaultRolesNotFoundException extends RuntimeException implements FriendlyExceptionInterface
{
    public function getName(): string
    {
        return 'Default roles not found.';
    }

    public function getSolution(): ?string
    {
        return <<<SOLUTION
You have to add roles with Manager::addRole() before using them as default.
SOLUTION;
    }
}
