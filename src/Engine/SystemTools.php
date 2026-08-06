<?php

declare(strict_types=1);

namespace Wpma\Engine;

/**
 * SystemTools — detects and wraps Linux CLI tools (find, grep) for fast file
 * discovery and pre-filtering. Falls back gracefully to PHP when unavailable.
 */
class SystemTools
{
    private static ?bool $execAvailable  = null;
    private static ?bool $findAvailable  = null;
    private static ?bool $grepAvailable  = null;

    // ── availability checks ───────────────────────────────────────────────────

    public static function isExecAvailable(): bool
    {
        if (self::$execAvailable !== null) {
            return self::$execAvailable;
        }

        // Check disabled_functions INI — no shell call needed
        $disabled = array_map('trim', explode(',', strtolower(ini_get('disable_functions') ?: '')));

        $execBlocked  = in_array('exec', $disabled, true);
        $shellBlocked = in_array('shell_exec', $disabled, true);

        if ($execBlocked && $shellBlocked) {
            return self::$execAvailable = false;
        }

        // Check functions actually exist in the runtime
        $execExists  = !$execBlocked  && function_exists('exec');
        $shellExists = !$shellBlocked && function_exists('shell_exec');

        if (!$execExists && !$shellExists) {
            return self::$execAvailable = false;
        }

        // On Windows, find/grep don't exist anyway — skip further checks
        if (DIRECTORY_SEPARATOR === '\\') {
            return self::$execAvailable = false;
        }

        return self::$execAvailable = true;
    }

    public static function isFindAvailable(): bool
    {
        if (self::$findAvailable !== null) {
            return self::$findAvailable;
        }

        if (!self::isExecAvailable()) {
            return self::$findAvailable = false;
        }

        // Check common locations without spawning a process
        $paths = ['/usr/bin/find', '/bin/find', '/usr/local/bin/find'];
        foreach ($paths as $p) {
            if (is_executable($p)) {
                return self::$findAvailable = true;
            }
        }

        return self::$findAvailable = false;
    }

    public static function isGrepAvailable(): bool
    {
        if (self::$grepAvailable !== null) {
            return self::$grepAvailable;
        }

        if (!self::isExecAvailable()) {
            return self::$grepAvailable = false;
        }

        // Check common locations without spawning a process
        $paths = ['/usr/bin/grep', '/bin/grep', '/usr/local/bin/grep'];
        foreach ($paths as $p) {
            if (is_executable($p)) {
                return self::$grepAvailable = true;
            }
        }

        return self::$grepAvailable = false;
    }

    // ── fast file discovery via `find` ────────────────────────────────────────

    /**
     * Use `find` to list all scannable files under $root.
     * Returns array of absolute paths, or null if find is unavailable.
     *
     * @param string   $root
     * @param string[] $excludeDirs       Directory basenames to exclude (e.g. ['node_modules', '.git'])
     * @param int      $maxFileSizeBytes
     * @return string[]|null
     */
    public static function findFiles(string $root, array $excludeDirs = [], int $maxFileSizeBytes = 10485760): ?array
    {
        if (!self::isFindAvailable()) {
            return null;
        }

        $root = escapeshellarg($root);

        // Build -prune expressions for excluded dirs
        $pruneExpr = '';
        foreach ($excludeDirs as $dir) {
            $escaped    = escapeshellarg($dir);
            $pruneExpr .= " -o -name {$escaped} -prune";
        }

        // Max file size in 512-byte blocks (find uses +N for "more than N blocks")
        // We use -size to skip files over the limit
        $maxBlocks = (int) ceil($maxFileSizeBytes / 512);

        // Find PHP-family files and .htaccess, excluding pruned dirs, within size limit
        $cmd = "find {$root} \\( -false{$pruneExpr} \\) -prune -o "
             . "\\( -name '*.php' -o -name '*.phtml' -o -name '*.php5' "
             . "-o -name '*.php7' -o -name '*.phar' -o -name '.htaccess' \\) "
             . "-not -size +{$maxBlocks}c "
             . "-readable -print 2>/dev/null";

        $output = @shell_exec($cmd);
        if ($output === null || $output === '') {
            return [];
        }

        $files = array_filter(array_map('trim', explode("\n", $output)));
        return array_values($files);
    }

    // ── fast pre-filter via `grep` ────────────────────────────────────────────

    /**
     * Use `grep -rl` to quickly find files containing any of the given patterns.
     * Returns array of matching file paths, or null if grep is unavailable.
     *
     * This is the key speedup: on a 10,000-file WP site, grep can identify the
     * ~50–200 suspicious files in seconds, so PHP only does deep analysis on those.
     *
     * @param string[] $files    List of files to search (from findFiles())
     * @param string[] $patterns Regex patterns to search for
     * @return string[]|null     Paths of files matching at least one pattern, or null on failure
     */
    public static function grepFiles(array $files, array $patterns): ?array
    {
        if (!self::isGrepAvailable() || empty($files) || empty($patterns)) {
            return null;
        }

        // Write file list to a temp file (avoids "argument list too long")
        $tmpList = tempnam(sys_get_temp_dir(), 'wpma_');
        if ($tmpList === false) {
            return null;
        }

        try {
            file_put_contents($tmpList, implode("\n", $files));

            // Build combined pattern: grep -E "pattern1|pattern2|..."
            $combined = implode('|', array_map('escapeshellarg', $patterns));
            // Note: using -e for each pattern is safer than combining
            $patternArgs = implode(' ', array_map(fn($p) => '-e ' . escapeshellarg($p), $patterns));

            $cmd    = "grep -rlE {$patternArgs} --files-from=" . escapeshellarg($tmpList) . " 2>/dev/null";
            $output = @shell_exec($cmd);

            if ($output === null) {
                return null;
            }

            $matches = array_filter(array_map('trim', explode("\n", $output)));
            return array_values($matches);
        } finally {
            @unlink($tmpList);
        }
    }

    /**
     * Summary of available tools for display in progress/debug output.
     */
    public static function summary(): string
    {
        $exec  = self::isExecAvailable() ? 'yes' : 'no';
        $find  = self::isFindAvailable()  ? 'yes' : 'no';
        $grep  = self::isGrepAvailable()  ? 'yes' : 'no';
        return "exec={$exec} find={$find} grep={$grep}";
    }
}
