<?php
namespace Yiisoft\Rbac;

/**
 * Common interface for authrization items:
 *
 * - Role
 * - Permission
 * - Rule
 */
interface ItemInterface
{
    public function getName(): string;
}
