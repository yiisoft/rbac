<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

use Yiisoft\Access\AccessCheckerInterface;

/**
 * Deny all access.
 */
final class DenyAll implements AccessCheckerInterface
{
    public function userHasPermission($userId, string $permissionName, array $parameters = []): bool
    {
        return false;
    }
}
