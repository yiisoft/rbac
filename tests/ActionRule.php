<?php

namespace Yiisoft\Rbac\Tests;

use Yiisoft\Rbac\Item;
use Yiisoft\Rbac\Rule;

/**
 * Description of ActionRule.
 */
class ActionRule extends Rule
{
    private const NAME = 'action_rule';

    private string $action;

    /**
     * Private and protected properties to ensure that serialized object
     * does not get corrupted after saving into the DB because of null-bytes
     * in the string.
     *
     * @see https://github.com/yiisoft/yii2/issues/10176
     * @see https://github.com/yiisoft/yii2/issues/12681
     */
    private $somePrivateProperty;
    protected $someProtectedProperty;

    public function __construct(string $action = 'read')
    {
        parent::__construct(self::NAME);
        $this->action = $action;
    }

    public function execute(string $userId, Item $item, array $parameters = []): bool
    {
        return $this->action === 'all' || $this->action === $parameters['action'];
    }
}
