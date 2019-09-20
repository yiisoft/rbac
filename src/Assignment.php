<?php
namespace Yiisoft\Rbac;

/**
 * Assignment represents an assignment of a role to a user.
 */
class Assignment
{
    /**
     * @var string the user ID. This should be a string representing
     * the unique identifier of a user.
     */
    private $userId;
    /**
     * @var string the role name
     */
    private $roleName;
    /**
     * @var int UNIX timestamp representing the assignment creation time
     */
    private $createdAt;

    public function __construct(string $userId, string $roleName)
    {
        $this->userId = $userId;
        $this->roleName = $roleName;
    }

    public function getUserId(): string
    {
        return $this->userId;
    }

    public function getRoleName(): string
    {
        return $this->roleName;
    }
}
