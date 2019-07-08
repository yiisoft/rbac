<?php
namespace Yiisoft\Rbac;

use Yiisoft\Access\CheckAccessInterface;

/**
 * Deny all access control.
 */
class DenyAll implements CheckAccessInterface
{
    public function checkAccess($userId, string $permissionName, array $parameters = []): bool
    {
        return false;
    }
}
