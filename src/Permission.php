<?php
namespace Yiisoft\Rbac;

/**
 * For more details and usage information on Permission, see the [guide article on security authorization](guide:security-authorization).
 */
class Permission extends Item
{
    /**
     * {@inheritdoc}
     */
    public $type = self::TYPE_PERMISSION;
}
