<?php

declare(strict_types=1);

namespace Wpma\WP;

/**
 * WpCoreIntegrityChecker — verifies WordPress core files against the
 * official WordPress.org core checksums API.
 *
 * API endpoint:
 *   https://api.wordpress.org/core/checksums/1.0/?version={v}&locale={l}
 *
 * The core API returns MD5 hashes (unlike the plugin API which has SHA-256).
 * We use MD5 comparison here — this matches what WP-CLI does.
 *
 * Result is returned as a PluginIntegrity object with:
 *   slug    = 'core'
 *   method  = 'core-api'
 *
 * Core scope:
 *   wp-admin/*, wp-includes/*, and the fixed set of root PHP files.
 *   wp-content/ is intentionally excluded — it is user content.
 */
class WpCoreIntegrityChecker
{
    private const CHECKSUMS_API   = 'https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s';
    private const DEFAULT_LOCALE  = 'en_US';
    private const API_TIMEOUT     = 15;

    /**
     * Root-level PHP files that are part of WP core.
     * wp-config.php is excluded — it is site-specific.
     */
    private const CORE_ROOT_FILES = [
        'index.php',
        'wp-activate.php',
        'wp-blog-header.php',
        'wp-comments-post.php',
        'wp-config-sample.php',
        'wp-cron.php',
        'wp-links-opml.php',
        'wp-load.php',
        'wp-login.php',
        'wp-mail.php',
        'wp-settings.php',
        'wp-signup.php',
        'wp-trackback.php',
        'xmlrpc.php',
    ];

    private const CORE_DIRS = ['wp-admin', 'wp-includes'];

    /**
     * Check WordPress core integrity for a WP installation root.
     *
     * @param  string $wpRoot  Absolute path to the WordPress root (directory
     *                         containing wp-config.php / wp-includes/)
     * @return PluginIntegrity Result object (slug='core', method='core-api')
     */
    public function check(string $wpRoot): PluginIntegrity
    {
        $wpRoot  = rtrim(str_replace('\\', '/', $wpRoot), '/');
        $version = $this->detectVersion($wpRoot);

        if ($version === '') {
            return new PluginIntegrity(PluginIntegrity::UNAVAILABLE, 'core', '', [], [], [], 'core-api');
        }

        $locale = $this->detectLocale($wpRoot);
        $url    = sprintf(self::CHECKSUMS_API, urlencode($version), urlencode($locale));

        [$httpStatus, $response] = $this->httpGetRaw($url);

        if ($response === null) {
            $status = ($httpStatus === 404)
                ? PluginIntegrity::UNAVAILABLE
                : PluginIntegrity::CHECKSUM_UNAVAILABLE;
            return new PluginIntegrity($status, 'core', $version, [], [], [], 'core-api');
        }

        $data = json_decode($response, true);
        if (!is_array($data) || empty($data['checksums'])) {
            return new PluginIntegrity(PluginIntegrity::UNAVAILABLE, 'core', $version, [], [], [], 'core-api');
        }

        // Build official MD5 map — only core paths (exclude wp-content/)
        /** @var array<string, string|null> $officialMd5  relPath => md5 */
        $officialMd5 = [];
        foreach ($data['checksums'] as $relPath => $md5) {
            $norm = ltrim(str_replace('\\', '/', $relPath), '/');
            if ($this->isCoreFile($norm)) {
                $officialMd5[$norm] = (string) $md5 !== '' ? (string) $md5 : null;
            }
        }

        // Enumerate local core files
        /** @var array<string, string> $localRelToAbs  relPath => absPath */
        $localRelToAbs = [];
        foreach (self::CORE_DIRS as $dir) {
            $absDir = $wpRoot . '/' . $dir;
            if (!is_dir($absDir)) {
                continue;
            }
            foreach ($this->enumerateFiles($absDir) as $absFile) {
                $rel                   = ltrim(substr(str_replace('\\', '/', $absFile), strlen($wpRoot)), '/');
                $localRelToAbs[$rel]   = $absFile;
            }
        }
        foreach (self::CORE_ROOT_FILES as $f) {
            $abs = $wpRoot . '/' . $f;
            if (is_file($abs)) {
                $localRelToAbs[$f] = $abs;
            }
        }

        // Set arithmetic
        $officialSet = array_flip(array_keys($officialMd5));
        $localSet    = array_flip(array_keys($localRelToAbs));

        $missingFiles  = array_keys(array_diff_key($officialSet, $localSet));
        $extraFiles    = array_keys(array_diff_key($localSet, $officialSet));
        $modifiedFiles = [];
        $verifiedFiles = [];
        $okCount       = 0;

        foreach (array_keys(array_intersect_key($officialSet, $localSet)) as $relPath) {
            $expectedMd5 = $officialMd5[$relPath];

            if ($expectedMd5 === null) {
                $okCount++; // no hash → treat as ok (unverifiable)
                $verifiedFiles[] = $relPath;
                continue;
            }

            $actualMd5 = @md5_file($localRelToAbs[$relPath]);
            if ($actualMd5 === false) {
                continue;
            }

            if ($actualMd5 === $expectedMd5) {
                $okCount++;
                $verifiedFiles[] = $relPath;
            } else {
                $modifiedFiles[] = $relPath;
            }
        }

        $hasProblems = !empty($modifiedFiles) || !empty($extraFiles) || !empty($missingFiles);
        $status      = $hasProblems ? PluginIntegrity::MODIFIED : PluginIntegrity::VERIFIED;

        return new PluginIntegrity(
            status:          $status,
            slug:            'core',
            version:         $version,
            modifiedFiles:   $modifiedFiles,
            unexpectedFiles: $extraFiles,
            missingFiles:    $missingFiles,
            method:          'core-api',
            officialCount:   count($officialMd5),
            localCount:      count($localRelToAbs),
            okCount:         $okCount,
            verifiedFiles:   $verifiedFiles,
        );
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private function isCoreFile(string $normPath): bool
    {
        foreach (self::CORE_DIRS as $dir) {
            if (str_starts_with($normPath, $dir . '/')) {
                return true;
            }
        }
        return in_array($normPath, self::CORE_ROOT_FILES, true);
    }

    private function detectVersion(string $wpRoot): string
    {
        $file = $wpRoot . '/wp-includes/version.php';
        if (!is_readable($file)) {
            return '';
        }
        $content = @file_get_contents($file, false, null, 0, 8192);
        if ($content === false) {
            return '';
        }
        if (preg_match('/\$wp_version\s*=\s*\'([^\']+)\'/', $content, $m)) {
            return trim($m[1]);
        }
        return '';
    }

    private function detectLocale(string $wpRoot): string
    {
        $config = $wpRoot . '/wp-config.php';
        if (is_readable($config)) {
            $content = @file_get_contents($config, false, null, 0, 65536);
            if ($content !== false
                && preg_match("/define\s*\(\s*['\"]WPLANG['\"]\s*,\s*['\"]([^'\"]+)['\"]/", $content, $m)
            ) {
                $locale = trim($m[1]);
                if ($locale !== '') {
                    return $locale;
                }
            }
        }
        return self::DEFAULT_LOCALE;
    }

    private function enumerateFiles(string $dir): array
    {
        $result = [];
        $stack  = [$dir];

        while (!empty($stack)) {
            $current = array_pop($stack);
            foreach (@scandir($current) ?: [] as $entry) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }
                $full = $current . '/' . $entry;
                if (is_dir($full)) {
                    $stack[] = $full;
                } elseif (is_file($full)) {
                    $result[] = $full;
                }
            }
        }

        return $result;
    }

    /**
     * Overridable HTTP fetch — protected so tests can inject mock responses.
     *
     * @return array{0: int, 1: string|null}  [HTTP status, body or null]
     */
    protected function httpGetRaw(string $url): array
    {
        $context = stream_context_create([
            'http' => [
                'timeout'         => self::API_TIMEOUT,
                'follow_location' => 1,
                'user_agent'      => 'WPMA/2.0 (+https://github.com/wpma)',
                'ignore_errors'   => true,
            ],
            'ssl'  => ['verify_peer' => true, 'verify_peer_name' => true],
        ]);

        $body = @file_get_contents($url, false, $context);

        if ($body === false) {
            return [0, null];
        }

        $status = 200;
        if (!empty($http_response_header)) {
            if (preg_match('/HTTP\/\S+\s+(\d+)/', $http_response_header[0], $m)) {
                $status = (int) $m[1];
            }
        }

        if ($status >= 400) {
            return [$status, null];
        }

        return [$status, $body !== '' ? $body : null];
    }
}
