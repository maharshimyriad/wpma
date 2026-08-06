<?php

declare(strict_types=1);

namespace Wpma\Engine;

use Wpma\Config\ScanConfig;
use Wpma\Models\ScanWarning;

/**
 * FileDiscovery — enumerates files in a target path, applying inclusion/exclusion
 * rules from ScanConfig and detecting symlink cycles.
 *
 * Only PHP-family files (.php, .phtml, .php5, .php7, .phar) and .htaccess files
 * are yielded; everything else is silently skipped unless it matches an explicit
 * excludeExtension (which also receives no warning).
 *
 * Usage:
 *   $discovery = new FileDiscovery($config);
 *   foreach ($discovery->discover('/path/to/scan', function(ScanWarning $w) { ... }) as $path) {
 *       // process $path
 *   }
 *   // Warnings are also available via:
 *   foreach ($discovery->warnings as $warning) { ... }
 */
class FileDiscovery
{
    /**
     * Extensions that are yielded for scanning (lowercase, without leading dot).
     */
    private const SCANNABLE_EXTENSIONS = ['php', 'phtml', 'php5', 'php7', 'phar'];

    /**
     * Bare filenames (no extension) that are always included regardless of extension rules.
     */
    private const SCANNABLE_FILENAMES = ['.htaccess'];

    /**
     * Non-fatal warnings collected during the last discover() call.
     * Each entry is a ScanWarning describing why a file or directory was skipped.
     *
     * @var ScanWarning[]
     */
    public array $warnings = [];

    public function __construct(private readonly ScanConfig $config) {}

    /**
     * Yield every file path that should be scanned under $rootPath.
     *
     * When $rootPath is a single file the file is yielded (if it passes checks)
     * and the generator returns.  When $rootPath is a directory the tree is walked
     * recursively with RecursiveDirectoryIterator.
     *
     * Warnings for skipped items are:
     *   - appended to $this->warnings
     *   - passed to $onWarning callback (if provided)
     *
     * @param string        $rootPath  Filesystem path to a file or directory.
     * @param callable|null $onWarning Optional callback invoked for each ScanWarning.
     *                                 Signature: function(ScanWarning $warning): void
     * @return \Generator<string> Yields absolute file paths as strings.
     */
    public function discover(string $rootPath, callable $onWarning = null): \Generator
    {
        // Reset warnings for each new discover() call.
        $this->warnings = [];

        // Track visited real paths to detect symlink cycles.
        /** @var array<string, true> $visitedRealPaths */
        $visitedRealPaths = [];

        if (is_file($rootPath)) {
            // Single-file mode: apply size/extension checks, then yield.
            yield from $this->processSingleFile($rootPath, $visitedRealPaths, $onWarning);
            return;
        }

        if (!is_dir($rootPath)) {
            // Path does not exist or is neither a file nor a directory.
            $this->emitWarning(
                new ScanWarning(
                    message:     "Path is not a file or directory: {$rootPath}",
                    filePath:    $rootPath,
                    warningType: 'skipped_permission',
                ),
                $onWarning,
            );
            return;
        }

        // Directory mode: walk recursively.
        yield from $this->walkDirectory($rootPath, $visitedRealPaths, $onWarning);
    }

    // ─────────────────────────────────────────────────── private helpers ─────

    /**
     * Append a ScanWarning to $this->warnings and, if a callback is registered,
     * invoke it with the same warning.
     */
    private function emitWarning(ScanWarning $warning, ?callable $onWarning): void
    {
        $this->warnings[] = $warning;
        if ($onWarning !== null) {
            ($onWarning)($warning);
        }
    }

    /**
     * Return true when the given filename/extension should be yielded for scanning.
     *
     * Rules:
     *   1. Always include bare filenames listed in SCANNABLE_FILENAMES (.htaccess).
     *   2. Include files whose (lowercase, dot-prefixed) extension is in SCANNABLE_EXTENSIONS.
     *   3. Exclude everything else.
     */
    private function isScannableFile(string $basename, string $ext): bool
    {
        if (in_array($basename, self::SCANNABLE_FILENAMES, true)) {
            return true;
        }
        return in_array($ext, self::SCANNABLE_EXTENSIONS, true);
    }

    /**
     * Check and yield a single file path.
     *
     * @param array<string, true> $visitedRealPaths
     * @return \Generator<string>
     */
    private function processSingleFile(
        string $filePath,
        array &$visitedRealPaths,
        ?callable $onWarning,
    ): \Generator {
        // Symlink cycle detection.
        if (is_link($filePath)) {
            $real = realpath($filePath);
            if ($real === false) {
                // Broken symlink — treat as unreadable.
                $this->emitWarning(
                    new ScanWarning(
                        message:     "Broken symlink, cannot resolve: {$filePath}",
                        filePath:    $filePath,
                        warningType: 'skipped_permission',
                    ),
                    $onWarning,
                );
                return;
            }
            if (isset($visitedRealPaths[$real])) {
                $this->emitWarning(
                    new ScanWarning(
                        message:     "Symlink cycle detected, skipping: {$filePath} → {$real}",
                        filePath:    $filePath,
                        warningType: 'skipped_symlink',
                    ),
                    $onWarning,
                );
                return;
            }
            $visitedRealPaths[$real] = true;
        }

        // Permission / readability check.
        if (!is_readable($filePath)) {
            $this->emitWarning(
                new ScanWarning(
                    message:     "File is not readable: {$filePath}",
                    filePath:    $filePath,
                    warningType: 'skipped_permission',
                ),
                $onWarning,
            );
            return;
        }

        // Extension filter (lowercase, dot-prefixed for excludeExtensions comparison).
        $ext      = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        $basename = basename($filePath);
        $dotExt   = $ext !== '' ? '.' . $ext : '';

        // Hard-excluded extensions (binary/media types) — silently skip, no warning.
        if ($dotExt !== '' && in_array($dotExt, $this->config->excludeExtensions, true)) {
            return;
        }

        // Size filter (checked before scannable-extension gate so oversized files
        // still emit a warning, including for non-PHP files that would otherwise
        // be silently skipped).
        $size = @filesize($filePath);
        if ($size === false) {
            $this->emitWarning(
                new ScanWarning(
                    message:     "Cannot determine file size: {$filePath}",
                    filePath:    $filePath,
                    warningType: 'skipped_permission',
                ),
                $onWarning,
            );
            return;
        }
        if ($size > $this->config->maxFileSizeBytes) {
            $this->emitWarning(
                new ScanWarning(
                    message:     "File exceeds max size ({$size} > {$this->config->maxFileSizeBytes} bytes): {$filePath}",
                    filePath:    $filePath,
                    warningType: 'skipped_size',
                ),
                $onWarning,
            );
            return;
        }

        // Scannable-extension gate: only yield PHP-family and .htaccess files.
        if (!$this->isScannableFile($basename, $ext)) {
            return;
        }

        yield $filePath;
    }

    /**
     * Walk a directory tree recursively and yield qualifying file paths.
     *
     * @param array<string, true> $visitedRealPaths
     * @return \Generator<string>
     */
    private function walkDirectory(
        string $dirPath,
        array &$visitedRealPaths,
        ?callable $onWarning,
    ): \Generator {
        try {
            $dirIterator = new \RecursiveDirectoryIterator(
                $dirPath,
                \RecursiveDirectoryIterator::SKIP_DOTS
                | \RecursiveDirectoryIterator::FOLLOW_SYMLINKS,
            );

            // Wrap with a filter that prunes excluded directories *before* the
            // RecursiveIteratorIterator descends into them.  The callback receives
            // an SplFileInfo; returning false for a directory causes the iterator
            // to skip both the directory entry and all of its children.
            $excludeDirs = $this->config->excludeDirs;
            $filtered    = new \RecursiveCallbackFilterIterator(
                $dirIterator,
                static function (\SplFileInfo $fileInfo) use ($excludeDirs): bool {
                    if ($fileInfo->isDir()) {
                        return !in_array($fileInfo->getFilename(), $excludeDirs, true);
                    }
                    return true;
                },
            );

            $iterator = new \RecursiveIteratorIterator(
                $filtered,
                \RecursiveIteratorIterator::LEAVES_ONLY,
            );
        } catch (\Exception $e) {
            $this->emitWarning(
                new ScanWarning(
                    message:     "Cannot open directory: {$dirPath} — " . $e->getMessage(),
                    filePath:    $dirPath,
                    warningType: 'skipped_permission',
                ),
                $onWarning,
            );
            return;
        }

        /** @var \SplFileInfo $fileInfo */
        foreach ($iterator as $fileInfo) {
            $currentPath = $fileInfo->getPathname();

            // ── symlink cycle detection for files ─────────────────────────────
            if ($fileInfo->isLink()) {
                $real = realpath($currentPath);
                if ($real === false) {
                    $this->emitWarning(
                        new ScanWarning(
                            message:     "Broken symlink, cannot resolve: {$currentPath}",
                            filePath:    $currentPath,
                            warningType: 'skipped_permission',
                        ),
                        $onWarning,
                    );
                    continue;
                }
                if (isset($visitedRealPaths[$real])) {
                    $this->emitWarning(
                        new ScanWarning(
                            message:     "Symlink cycle detected, skipping: {$currentPath} → {$real}",
                            filePath:    $currentPath,
                            warningType: 'skipped_symlink',
                        ),
                        $onWarning,
                    );
                    continue;
                }
                $visitedRealPaths[$real] = true;
            }

            // ── permission check ──────────────────────────────────────────────
            try {
                if (!$fileInfo->isReadable()) {
                    $this->emitWarning(
                        new ScanWarning(
                            message:     "File is not readable: {$currentPath}",
                            filePath:    $currentPath,
                            warningType: 'skipped_permission',
                        ),
                        $onWarning,
                    );
                    continue;
                }
            } catch (\Exception $e) {
                $this->emitWarning(
                    new ScanWarning(
                        message:     "Permission error on file: {$currentPath} — " . $e->getMessage(),
                        filePath:    $currentPath,
                        warningType: 'skipped_permission',
                    ),
                    $onWarning,
                );
                continue;
            }

            // ── excluded-extension filter (binary/media types) ────────────────
            $ext    = strtolower($fileInfo->getExtension());
            $dotExt = $ext !== '' ? '.' . $ext : '';

            if ($dotExt !== '' && in_array($dotExt, $this->config->excludeExtensions, true)) {
                continue; // Silently skip expected binary/media extensions.
            }

            // ── size filter ───────────────────────────────────────────────────
            try {
                $size = $fileInfo->getSize();
            } catch (\RuntimeException $e) {
                $this->emitWarning(
                    new ScanWarning(
                        message:     "Cannot determine file size: {$currentPath} — " . $e->getMessage(),
                        filePath:    $currentPath,
                        warningType: 'skipped_permission',
                    ),
                    $onWarning,
                );
                continue;
            }

            if ($size > $this->config->maxFileSizeBytes) {
                $this->emitWarning(
                    new ScanWarning(
                        message:     "File exceeds max size ({$size} > {$this->config->maxFileSizeBytes} bytes): {$currentPath}",
                        filePath:    $currentPath,
                        warningType: 'skipped_size',
                    ),
                    $onWarning,
                );
                continue;
            }

            // Track real path for all files (including non-symlinks) so a symlink
            // pointing to an already-visited regular file is caught as a cycle.
            $real = realpath($currentPath);
            if ($real !== false) {
                if (isset($visitedRealPaths[$real])) {
                    $this->emitWarning(
                        new ScanWarning(
                            message:     "Symlink cycle detected (real path already visited): {$currentPath} → {$real}",
                            filePath:    $currentPath,
                            warningType: 'skipped_symlink',
                        ),
                        $onWarning,
                    );
                    continue;
                }
                $visitedRealPaths[$real] = true;
            }

            // ── scannable-extension gate ──────────────────────────────────────
            // Only yield PHP-family files and .htaccess; everything else is
            // silently skipped (it is not a warning — it is simply out of scope).
            $basename = $fileInfo->getFilename();
            if (!$this->isScannableFile($basename, $ext)) {
                continue;
            }

            yield $currentPath;
        }
    }
}
