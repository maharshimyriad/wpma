<?php

declare(strict_types=1);

namespace Wpma\WP;

/**
 * PluginIntegrityChecker — checks plugin integrity against WordPress.org checksums.
 *
 * Strategy:
 *   1. WordPress.org Checksum API — sha256 comparison, all file types, no extension filter
 *   2. WP-CLI verify-checksums (fallback when API unreachable)
 *   3. UNAVAILABLE — premium/custom/private plugins (API returns 404)
 *   4. CHECKSUM_UNAVAILABLE — API is reachable but returns a network or server error
 *
 * Key correctness rules:
 *   - Enumerates ALL local files regardless of extension (catches extensionless malware)
 *   - Normalises path separators before comparison (Windows \ vs Linux /)
 *   - Uses ONLY sha256 from the API response — never falls back to md5
 *   - Files in the official manifest that lack a sha256 key are tracked (prevent false EXTRA)
 *     but excluded from hash comparison (cannot verify without sha256)
 *   - Status is MODIFIED whenever modified, extra, OR missing files exist
 *   - CHECKSUM_UNAVAILABLE is returned when the manifest API is unreachable (network/5xx)
 *     so that no false EXTRA findings are generated
 */
class PluginIntegrityChecker
{
    private const WPORG_CHECKSUM_API = 'https://downloads.wordpress.org/plugin-checksums/%s/%s.json';
    private const WPORG_INFO_API     = 'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=%s&request[fields][versions]=false';
    private const API_TIMEOUT        = 10; // seconds

    /** @var array<string, PluginIntegrity> Cache per slug@version */
    private array $cache = [];

    /**
     * Check integrity for a plugin directory.
     *
     * @param string $pluginDir  Absolute path to the plugin directory (no trailing slash)
     * @param string $wpRoot     WordPress root path (for WP-CLI fallback)
     */
    public function check(string $pluginDir, string $wpRoot = ''): PluginIntegrity
    {
        $pluginDir = rtrim(str_replace('\\', '/', $pluginDir), '/');

        [$slug, $version] = $this->detectSlugAndVersion($pluginDir);

        if ($slug === '') {
            return new PluginIntegrity(PluginIntegrity::UNAVAILABLE, '', '', [], [], [], 'unavailable');
        }

        $cacheKey = "{$slug}@{$version}";
        if (isset($this->cache[$cacheKey])) {
            return $this->cache[$cacheKey];
        }

        // checkViaApi returns:
        //   PluginIntegrity — successful check
        //   null            — 404 / plugin not on WP.org  → UNAVAILABLE
        //   false           — network / server error       → CHECKSUM_UNAVAILABLE
        $apiResult        = $this->checkViaApi($pluginDir, $slug, $version);
        $checksumApiError = ($apiResult === false);

        $result = ($apiResult instanceof PluginIntegrity) ? $apiResult : null;

        // WP-CLI fallback only when the API failed operationally.
        // Do not run it for a definitive "not on WordPress.org" response.
        if ($result === null && $apiResult === false && $wpRoot !== '' && $this->isWpCliAvailable()) {
            $result = $this->checkViaWpCli($slug, $wpRoot);
        }

        // Final fallback — distinguish "not on WP.org" from operational failures.
        if ($result === null) {
            $status = $apiResult === false
                ? PluginIntegrity::CHECKSUM_UNAVAILABLE
                : PluginIntegrity::UNAVAILABLE;
            $result = new PluginIntegrity($status, $slug, $version, [], [], [], 'unavailable');
        }

        $this->cache[$cacheKey] = $result;
        return $result;
    }

    // ── Private: slug/version detection ──────────────────────────────────────

    /** @return array{0: string, 1: string} [slug, version] */
    private function detectSlugAndVersion(string $pluginDir): array
    {
        $slug    = basename($pluginDir);
        $version = '';

        $mainFile = $pluginDir . '/' . $slug . '.php';
        if (!is_readable($mainFile)) {
            $mainFile = $this->findMainPluginFile($pluginDir);
        }

        if ($mainFile !== '' && is_readable($mainFile)) {
            $headers = $this->readPluginHeaders($mainFile);
            $version = $headers['version'] ?? '';
            if (!empty($headers['text_domain'])) {
                $slug = $headers['text_domain'];
            }
        }

        return [$slug, $version];
    }

    private function findMainPluginFile(string $pluginDir): string
    {
        if (!is_dir($pluginDir)) {
            return '';
        }
        foreach (@glob($pluginDir . '/*.php') ?: [] as $file) {
            $content = @file_get_contents($file, false, null, 0, 4096);
            if ($content !== false && str_contains($content, 'Plugin Name:')) {
                return $file;
            }
        }
        return '';
    }

    /** @return array<string, string> */
    private function readPluginHeaders(string $file): array
    {
        $content = @file_get_contents($file, false, null, 0, 8192);
        if ($content === false) {
            return [];
        }
        $headers = [];
        foreach (['Plugin Name' => 'name', 'Version' => 'version', 'Text Domain' => 'text_domain'] as $h => $k) {
            if (preg_match('/^[ \t\/*#@]*' . preg_quote($h, '/') . '\s*:\s*(.+)$/mi', $content, $m)) {
                $headers[$k] = trim($m[1]);
            }
        }
        return $headers;
    }

    // ── Private: API checksum check ───────────────────────────────────────────

    /**
     * @return PluginIntegrity  — successful check
     *         null             — 404 / plugin not on WP.org
     *         false            — network or server error (CHECKSUM_UNAVAILABLE)
     */
    private function checkViaApi(string $pluginDir, string $slug, string $version): PluginIntegrity|null|false
    {
        if ($version === '') {
            [$versionStatus, $resolvedVersion] = $this->fetchLatestVersion($slug);
            if ($resolvedVersion === '') {
                return $versionStatus === 404 ? null : false;
            }
            $version = $resolvedVersion;
        }

        $url = sprintf(self::WPORG_CHECKSUM_API, urlencode($slug), urlencode($version));
        [$httpStatus, $response] = $this->httpGetRaw($url);

        if ($response === null) {
            // 404 = plugin not on WordPress.org  → signal null (→ UNAVAILABLE)
            // 0   = network unreachable           → signal false (→ CHECKSUM_UNAVAILABLE)
            // 5xx = server error                  → signal false (→ CHECKSUM_UNAVAILABLE)
            return $httpStatus === 404 ? null : false;
        }

        $data = json_decode($response, true);
        if (!\is_array($data) || empty($data['files'])) {
            return null;
        }

        // ── Build official checksum map (sha256 ONLY — no md5 fallback) ───────
        //
        // Keys:   normalised relative path (forward slashes)
        // Values: sha256 string, OR null when the API entry has no sha256 key.
        //
        // Rationale for null:
        //   - The path IS included in the official manifest → must not appear as EXTRA.
        //   - But sha256 is absent → cannot verify → excluded from hash comparison.
        //   - Treating such a file as OK is safer than a false MODIFIED.
        //
        /** @var array<string, string|null> $officialChecksums  relPath => sha256|null */
        $officialChecksums = [];

        foreach ($data['files'] as $relPath => $checksumObj) {
            $normPath = $this->normalisePath($relPath);
            $sha256   = is_array($checksumObj) ? ($checksumObj['sha256'] ?? null) : null;
            $officialChecksums[$normPath] = $sha256;
        }

        // ── Enumerate ALL local files (no extension filter) ───────────────────
        $localFiles = $this->enumerateAllFiles($pluginDir);

        /** @var array<string, string> $localRelToAbs  relPath => absPath */
        $localRelToAbs = [];
        foreach ($localFiles as $absPath) {
            $normAbs = $this->normalisePath($absPath);
            $normDir = $this->normalisePath($pluginDir);
            $rel     = ltrim(substr($normAbs, strlen($normDir)), '/');
            $localRelToAbs[$rel] = $absPath;
        }

        // ── Set arithmetic + hash comparison ─────────────────────────────────
        $diff = $this->computeChecksumDiff($officialChecksums, $localRelToAbs);

        $modifiedFiles = $diff['modified'];
        $missingFiles  = $diff['missing'];
        $extraFiles    = $diff['extra'];
        $okCount       = $diff['okCount'];

        // Status is MODIFIED whenever any category has problems.
        // A plugin with only missing files is NOT "verified" — files are absent.
        $hasProblems = !empty($modifiedFiles) || !empty($extraFiles) || !empty($missingFiles);
        $status      = $hasProblems ? PluginIntegrity::MODIFIED : PluginIntegrity::VERIFIED;

        return new PluginIntegrity(
            status:           $status,
            slug:             $slug,
            version:          $version,
            modifiedFiles:    $modifiedFiles,
            unexpectedFiles:  $extraFiles,
            missingFiles:     $missingFiles,
            method:           'api',
            officialCount:    count($officialChecksums),
            localCount:       count($localRelToAbs),
            okCount:          $okCount,
        );
    }

    /**
     * Pure SHA-256 comparison — no HTTP, no I/O beyond reading file hashes.
     *
     * @param array<string, string|null> $officialChecksums  relPath → sha256 (or null if unavailable)
     * @param array<string, string>      $localRelToAbs      relPath → absolute path on disk
     * @return array{modified: string[], missing: string[], extra: string[], okCount: int}
     */
    private function computeChecksumDiff(array $officialChecksums, array $localRelToAbs): array
    {
        $officialSet = array_flip(array_keys($officialChecksums));
        $localSet    = array_flip(array_keys($localRelToAbs));

        // Files in official manifest but absent on disk
        $missingFiles = array_keys(array_diff_key($officialSet, $localSet));

        // Files on disk but absent from official manifest
        $extraFiles   = array_keys(array_diff_key($localSet, $officialSet));

        // Files present in both — compare sha256 where available
        $modifiedFiles = [];
        $okCount       = 0;

        foreach (array_keys(array_intersect_key($officialSet, $localSet)) as $relPath) {
            $expectedSha256 = $officialChecksums[$relPath];

            if ($expectedSha256 === null) {
                // No sha256 in API response for this file — cannot verify; treat as OK.
                $okCount++;
                continue;
            }

            $absPath      = $localRelToAbs[$relPath];
            $actualSha256 = hash_file('sha256', $absPath);

            if ($actualSha256 === false) {
                // Cannot read file (permission error) — skip without flagging
                continue;
            }

            if ($actualSha256 === $expectedSha256) {
                $okCount++;
            } else {
                $modifiedFiles[] = $relPath;
            }
        }

        return [
            'modified' => $modifiedFiles,
            'missing'  => $missingFiles,
            'extra'    => $extraFiles,
            'okCount'  => $okCount,
        ];
    }

    /** @return array{0: int, 1: string} */
    private function fetchLatestVersion(string $slug): array
    {
        $url = sprintf(self::WPORG_INFO_API, urlencode($slug));
        [$httpStatus, $response] = $this->httpGetRaw($url);
        if ($response === null) {
            return [$httpStatus, ''];
        }

        $data = json_decode($response, true);
        $version = is_array($data) ? (string) ($data['version'] ?? '') : '';

        return [200, $version];
    }

    // ── Private: local file enumeration (ALL files, no extension filter) ──────

    /**
     * Recursively enumerate every regular file under $dir.
     * No extension filter — extensionless files, .log, .dat etc. are all included.
     *
     * @return string[]  Absolute paths
     */
    private function enumerateAllFiles(string $dir): array
    {
        $result = [];
        $stack  = [$dir];

        while (!empty($stack)) {
            $current = array_pop($stack);
            $entries = @scandir($current) ?: [];

            foreach ($entries as $entry) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }

                $full = $current . '/' . $entry;

                if (is_link($full)) {
                    // Follow symlinks but skip if target is outside plugin dir to avoid loops
                    $real = realpath($full);
                    if ($real === false || !str_starts_with($real, $dir)) {
                        continue;
                    }
                    $full = $real;
                }

                if (is_dir($full)) {
                    $stack[] = $full;
                } elseif (is_file($full)) {
                    $result[] = $full;
                }
            }
        }

        return $result;
    }

    // ── Private: path normalisation ───────────────────────────────────────────

    /**
     * Normalise a path to forward slashes and remove any trailing slash.
     * This ensures Windows paths (plugin-fw\templates\c) match the API paths
     * (plugin-fw/templates/c) correctly.
     */
    private function normalisePath(string $path): string
    {
        return rtrim(str_replace('\\', '/', $path), '/');
    }

    // ── Private: WP-CLI fallback ──────────────────────────────────────────────

    protected function checkViaWpCli(string $slug, string $wpRoot): ?PluginIntegrity
    {
        $cmd = $this->buildWpCliVerifyCommand($slug, $wpRoot);
        [$exitCode, $output] = $this->executeCommand($cmd);

        $trimmedOutput = trim($output);
        if ($trimmedOutput === '') {
            return $exitCode === 0
                ? null
                : new PluginIntegrity(PluginIntegrity::CHECKSUM_UNAVAILABLE, $slug, '', [], [], [], 'wpcli');
        }

        if ($exitCode !== 0 && $this->isWpCliOperationalError($trimmedOutput)) {
            return new PluginIntegrity(PluginIntegrity::CHECKSUM_UNAVAILABLE, $slug, '', [], [], [], 'wpcli');
        }

        $modifiedFiles = [];
        foreach (array_filter(array_map('trim', explode("\n", $trimmedOutput))) as $line) {
            if ((str_contains($line, 'Warning') || str_contains($line, 'Error'))
                && preg_match('/\'([^\']+)\'/', $line, $m)
            ) {
                $modifiedFiles[] = $m[1];
            }
        }

        $status = empty($modifiedFiles) ? PluginIntegrity::VERIFIED : PluginIntegrity::MODIFIED;

        return new PluginIntegrity(
            status:        $status,
            slug:          $slug,
            version:       '',
            modifiedFiles: $modifiedFiles,
            method:        'wpcli',
        );
    }

    protected function isWpCliAvailable(): bool
    {
        static $available = null;
        if ($available !== null) {
            return $available;
        }

        $disabled = array_map('trim', explode(',', strtolower(ini_get('disable_functions') ?: '')));
        if (\in_array('exec', $disabled, true) || !function_exists('exec')) {
            return $available = false;
        }

        [$exitCode, $output] = $this->executeCommand($this->buildWpCliDiscoveryCommand());

        return $available = ($exitCode === 0 && trim($output) !== '');
    }

    /** @return array{0: int, 1: string} */
    protected function executeCommand(string $cmd): array
    {
        $lines = [];
        $exitCode = 0;
        @exec($cmd, $lines, $exitCode);

        return [$exitCode, implode("\n", $lines)];
    }

    protected function buildWpCliVerifyCommand(string $slug, string $wpRoot): string
    {
        $wpRoot = $this->normalisePathForWpCli($wpRoot);

        return sprintf(
            'wp --path=%s plugin verify-checksums %s --format=json 2>&1',
            escapeshellarg($wpRoot),
            escapeshellarg($slug)
        );
    }

    protected function buildWpCliDiscoveryCommand(): string
    {
        return PHP_OS_FAMILY === 'Windows'
            ? 'where wp 2>&1'
            : 'command -v wp 2>&1';
    }

    protected function normalisePathForWpCli(string $path): string
    {
        $path = trim($path);

        if (PHP_OS_FAMILY === 'Windows' && preg_match('#^/([a-zA-Z])/(.*)$#', $path, $m)) {
            $path = strtoupper($m[1]) . ':/' . $m[2];
        }

        return rtrim(str_replace('\\', '/', $path), '/');
    }

    protected function isWpCliOperationalError(string $output): bool
    {
        $needles = [
            'The system cannot find the path specified.',
            'This does not seem to be a WordPress installation.',
            'not recognized as an internal or external command',
            'Could not open input file',
            'Fatal error',
        ];

        foreach ($needles as $needle) {
            if (str_contains($output, $needle)) {
                return true;
            }
        }

        return false;
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────────

    /**
     * Fetch a URL and return [HTTP status code, response body].
     *
     * Return values:
     *   [200, string]  — success
     *   [404, null]    — not found
     *   [5xx, null]    — server error
     *   [0,   null]    — network unreachable (no HTTP response)
     *
     * Overridable in tests (protected) so the network layer can be mocked.
     *
     * @return array{0: int, 1: string|null}
     */
    protected function httpGetRaw(string $url): array
    {
        $context  = stream_context_create([
            'http' => [
                'timeout'         => self::API_TIMEOUT,
                'follow_location' => 1,
                'user_agent'      => 'WPMA/2.0 (+https://github.com/wpma)',
                'ignore_errors'   => true,
            ],
            'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
        ]);

        $body = @file_get_contents($url, false, $context);

        if ($body === false) {
            return [0, null]; // network unreachable
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

    /**
     * Thin wrapper — returns only the body (null on any failure).
     * Used by fetchLatestVersion which does not need to distinguish error types.
     */
    private function httpGet(string $url): ?string
    {
        [, $body] = $this->httpGetRaw($url);
        return $body;
    }
}
