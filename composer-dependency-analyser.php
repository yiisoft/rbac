<?php

declare(strict_types=1);

use ShipMonk\ComposerDependencyAnalyser\Config\Configuration;
use ShipMonk\ComposerDependencyAnalyser\Config\ErrorType;

return (new Configuration())
    ->disableComposerAutoloadPathScan()
    ->setFileExtensions(['php'])
    ->addPathToScan(__DIR__ . '/config', isDev: false)
    ->addPathToScan(__DIR__ . '/src', isDev: false)
    ->addPathToScan(__DIR__ . '/tests', isDev: true)
    // `psr/clock` is an optional integration (see "suggest" in composer.json): it's only used as a nullable
    // type-hint in `Manager`, so it's intentionally kept in "require-dev" instead of "require".
    ->ignoreErrorsOnPackages(['psr/clock'], [ErrorType::DEV_DEPENDENCY_IN_PROD]);
