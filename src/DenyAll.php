<?php
/**
 * @link http://www.yiiframework.com/
 *
 * @copyright Copyright (c) 2008 Yii Software LLC
 * @license http://www.yiiframework.com/license/
 */

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
