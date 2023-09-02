<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Support;

use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\RuleFactoryInterface;
use Yiisoft\Rbac\RuleInterface;

/**
 * Checks if authorID matches userID passed via params.
 */
class AuthorRule implements RuleInterface
{
    public function execute(string $userId, Item $item, RuleFactoryInterface $ruleFactory, array $parameters = []): bool
    {
        return $parameters['authorID'] == $userId;
    }
}
