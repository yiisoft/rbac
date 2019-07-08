<?php
use Yiisoft\Db\Migration;
use Yiisoft\Rbac\BaseManager;
use Yiisoft\Rbac\DbManager;
use Yiisoft\Rbac\Exceptions\InvalidConfigException;

/**
 * Adds index on `user_id` column in `auth_assignment` table for performance reasons.
 *
 * @see https://github.com/yiisoft/yii2/pull/14765
 */
class m170907_052038_rbac_add_index_on_auth_assignment_user_id extends Migration
{
    public $column = 'user_id';
    public $index = 'auth_assignment_user_id_idx';

    protected $authManager;

    public function __construct(BaseManager $authManager)
    {
        $this->authManager = $authManager;
        if (!$this->authManager instanceof DbManager) {
            throw new InvalidConfigException('You should configure "authManager" component to use database before executing this migration.');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function up()
    {
        $this->createIndex($this->index, $this->authManager->assignmentTable, $this->column);
    }

    /**
     * {@inheritdoc}
     */
    public function down()
    {
        $this->dropIndex($this->index, $this->authManager->assignmentTable);
    }
}
