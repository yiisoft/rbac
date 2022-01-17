<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests\Support;

use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\Rule;

/**
 * Checks if authorID matches userID passed via params.
 */
class AuthorRule extends Rule
{
    private const NAME = 'isAuthor';

    private bool $reallyReally;

    public function __construct($name = self::NAME, $reallyReally = false)
    {
        parent::__construct($name);
        $this->reallyReally = $reallyReally;
    }

    public function execute(string $userId, Item $item, array $parameters = []): bool
    {
        return $parameters['authorID'] == $userId;
    }

    public function withReallyReally(bool $reallyReally): self
    {
        $new = clone $this;
        $new->reallyReally = $reallyReally;
        return $new;
    }

    public function isReallyReally(): bool
    {
        return $this->reallyReally;
    }
}
