<?php

namespace Yiisoft\Rbac;

use Yiisoft\Access\AccessCheckerInterface;

/**
 * Deny all access control.
 */
class DenyAll implements AccessCheckerInterface
{
    public function userHasPermission($userId, string $permissionName, array $parameters = []): bool
    {
        return false;
    }
}
