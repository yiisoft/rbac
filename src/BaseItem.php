<?php
namespace Yiisoft\Rbac;

/**
 * BaseItem with constructor that sets properties by given array.
 */
abstract class BaseItem
{
    public function __construct(array $values = [])
    {
        foreach ($values as $key => $value) {
            $this->{$key} = $value;
        }
    }
}
