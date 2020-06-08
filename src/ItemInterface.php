<?php

declare(strict_types=1);

namespace Yiisoft\Rbac;

/**
 * Common interface for authorization items:
 *
 * - Role
 * - Permission
 * - Rule
 */
interface ItemInterface
{
    /**
     * @return string Authorization item name.
     */
    public function getName(): string;

    /**
     * @return array Authorization item attribute values indexed by attribute names.
     */
    public function getAttributes(): array;
}
