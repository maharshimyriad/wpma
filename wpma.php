#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * WPMA — WordPress Malware Analysis CLI
 *
 * Entry-point script. Bootstraps the Composer autoloader and delegates
 * control to the Symfony Console application.
 *
 * Usage:
 *   php wpma.php scan /path/to/wordpress
 *   php wpma.php --help
 */

// Locate the Composer autoloader relative to this script.
$autoloadCandidates = [
    __DIR__ . '/vendor/autoload.php',
    __DIR__ . '/../vendor/autoload.php',
];

$autoloaderFound = false;
foreach ($autoloadCandidates as $candidate) {
    if (file_exists($candidate)) {
        require_once $candidate;
        $autoloaderFound = true;
        break;
    }
}

if (!$autoloaderFound) {
    fwrite(STDERR, "Error: Composer autoloader not found.\n");
    fwrite(STDERR, "Run `composer install` before using WPMA.\n");
    exit(2);
}

// Hand off to the CLI application.
\Wpma\Cli\Application::main();
