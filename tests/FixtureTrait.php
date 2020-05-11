<?php

declare(strict_types=1);

namespace Yiisoft\Rbac\Tests;

use Yiisoft\Files\FileHelper;

trait FixtureTrait {

    private string $dataPath;

    private function getDataPath(): string
    {
        return sys_get_temp_dir() . '/' . str_replace('\\', '_', get_class($this)) . uniqid('', false);
    }

    private function getFixturesDirectory(): string
    {
        return __DIR__ . '/Fixtures/';
    }

    private function addFixturesFiles(): void
    {
        $this->dataPath = $this->getDataPath();
        FileHelper::copyDirectory($this->getFixturesDirectory(), $this->dataPath);
    }

    private function clearFixturesFiles(): void
    {
        FileHelper::removeDirectory($this->dataPath);
    }
}
