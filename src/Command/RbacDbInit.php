<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Command;

use InvalidArgumentException;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Yiisoft\Rbac\SchemaManagerInterface;

/**
 * Command for creating RBAC related database tables.
 */
final class RbacDbInit extends Command
{
    protected static $defaultName = 'rbac/db/init';

    /**
     * @throws InvalidArgumentException When a table name is set to the empty string.
     */
    public function __construct(
        private SchemaManagerInterface $schemaManager,
    ) {
        $this->schemaManager = $this->schemaManager;

        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->setDescription('Create RBAC schemas')
            ->setHelp('This command creates schemas for RBAC')
            ->addOption(name: 'force', shortcut: 'f', description: 'Force recreation of schemas if they exist');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        /** @var bool $force */
        $force = $input->getOption('force');
        if ($force === true) {
            $this->dropTable($this->schemaManager->getItemsChildrenTable(), $output);
            $this->dropTable($this->schemaManager->getAssignmentsTable(), $output);
            $this->dropTable($this->schemaManager->getItemsTable(), $output);
        }

        $this->createTable($this->schemaManager->getItemsTable(), $output);
        $this->createTable($this->schemaManager->getItemsChildrenTable(), $output);
        $this->createTable($this->schemaManager->getAssignmentsTable(), $output);

        $output->writeln('<fg=green>DONE</>');

        return Command::SUCCESS;
    }

    /**
     * Basic method for creating RBAC related table. When a table already exists, creation is skipped. Operations are
     * accompanied by explanations printed to console.
     *
     * @param string $tableName A name of created table.
     * @psalm-param non-empty-string $tableName
     *
     * @param OutputInterface $output Output for writing messages.
     */
    private function createTable(string $tableName, OutputInterface $output): void
    {
        $output->writeln("<fg=blue>Checking existence of `$tableName` table...</>");

        if ($this->schemaManager->tableExists($tableName)) {
            $output->writeln("<bg=yellow>`$tableName` table already exists. Skipped creating.</>");

            return;
        }

        $output->writeln("<fg=blue>`$tableName` table doesn't exist. Creating...</>");

        match ($tableName) {
            $this->schemaManager->getItemsTable() => $this->schemaManager->createItemsTable(),
            $this->schemaManager->getAssignmentsTable() => $this->schemaManager->createAssignmentsTable(),
            $this->schemaManager->getItemsChildrenTable() => $this->schemaManager->createItemsChildrenTable(),
        };

        $output->writeln("<bg=green>`$tableName` table has been successfully created.</>");
    }

    /**
     * Basic method for dropping RBAC related table. When a table doesn't exist, dropping is skipped. Operations are
     * accompanied by explanations printed to console.
     *
     * @param string $tableName A name of created table.
     * @psalm-param non-empty-string $tableName
     *
     * @param OutputInterface $output Output for writing messages.
     */
    private function dropTable(string $tableName, OutputInterface $output): void
    {
        $output->writeln("<fg=blue>Checking existence of `$tableName` table...</>");

        if (!$this->schemaManager->tableExists($tableName)) {
            $output->writeln("<bg=yellow>`$tableName` table doesn't exist. Skipped dropping.</>");

            return;
        }

        $output->writeln("<fg=blue>`$tableName` table exists. Dropping...</>");

        $this->schemaManager->dropTable($tableName);

        $output->writeln("<bg=green>`$tableName` table has been successfully dropped.</>");
    }
}
