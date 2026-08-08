<?php

declare(strict_types=1);

namespace Wpma\Engine;

use Wpma\Config\ScanConfig;
use Wpma\Detectors\DetectorInterface;
use Wpma\Detectors\PluginIntegrityDetector;
use Wpma\Engine\SystemTools;
use Wpma\Models\ScanReport;
use Wpma\Models\ScanWarning;
use Wpma\Cli\ScanTargetType;
use Wpma\Pipeline\PipelineRunner;
use Wpma\WP\PluginIntegrity;
use Wpma\WP\PluginIntegrityChecker;
use Wpma\WP\WpCoreIntegrityChecker;
use Wpma\WP\UploadsAnomalyScanner;

/**
 * ScanOrchestrator — wires FileDiscovery → PipelineRunner → Detectors → RiskEngine → ScanReport.
 */
class ScanOrchestrator
{
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

    /** @param DetectorInterface[] $detectors */
    public function __construct(
        private readonly ScanConfig             $config,
        private readonly array                  $detectors,
        private readonly PipelineRunner         $pipeline           = new PipelineRunner(),
        private readonly RiskEngine             $riskEngine         = new RiskEngine(),
        private readonly ?string                $fileListPath       = null,
        private readonly ?string                $suspiciousListPath = null,
        private readonly PluginIntegrityChecker $integrityChecker   = new PluginIntegrityChecker(),
        private readonly WpCoreIntegrityChecker $coreChecker        = new WpCoreIntegrityChecker(),
        private readonly ?ScanProgress          $progress           = null,
    ) {}

    /** @var array<string, PluginIntegrity> slug => integrity */
    private array $pluginIntegrityResults = [];

    /** @var array<string, array{pluginDir: string, wpRoot: string}> slug => target */
    private array $pluginIntegrityTargets = [];

    /** @var array<string, true> */
    private array $malwareAnalysisSkippedPlugins = [];

    private ?string $verifiedCoreRoot = null;

    public function getPluginIntegrityResults(): array
    {
        return $this->pluginIntegrityResults;
    }

    public function scan(?callable $onProgress = null): ScanReport
    {
        $startedAt  = new \DateTimeImmutable();
        $startMs    = microtime(true) * 1000;
        $warnings   = [];
        $allIocs    = [];
        $rawResults = [];
        $skipped    = 0;
        $done       = 0;

        // ── File list source ──────────────────────────────────────────────────
        // Priority 1: pre-built file list passed from shell wrapper (find+grep done in bash)
        // Priority 2: fast path using PHP exec + find/grep
        // Priority 3: pure PHP RecursiveDirectoryIterator fallback
        $files = null;

        $shellDiscoveryRendered = $this->fileListPath !== null && $this->suspiciousListPath !== null;

        if (!$shellDiscoveryRendered) {
            $this->progress?->beginFileDiscovery();
        }

        if ($this->fileListPath !== null && is_readable($this->fileListPath)) {
            $raw   = file_get_contents($this->fileListPath);
            $files = array_values(array_filter(array_map('trim', explode("\n", $raw ?: ''))));
        } elseif (SystemTools::isFindAvailable()) {
            $files = SystemTools::findFiles(
                $this->config->target,
                $this->config->excludeDirs,
                $this->config->maxFileSizeBytes,
            );
        }

        if ($files === null) {
            $discovery = new FileDiscovery($this->config);
            $fileGen   = $discovery->discover(
                $this->config->target,
                function (ScanWarning $w) use (&$warnings, &$skipped): void {
                    $warnings[] = $w;
                    $skipped++;
                }
            );
            $files = iterator_to_array($fileGen);
        }

        $files = $this->restrictFilesToTargetScope($files);

        $discoveredTotal = count($files);
        $this->progress?->noteFileDiscoveryResult($discoveredTotal);

        if (!$shellDiscoveryRendered) {
            $this->progress?->completeFileDiscovery($discoveredTotal);
        }

        // ── Optional grep pre-filter ──────────────────────────────────────────
        // Run grep across ALL files to find which ones contain suspicious patterns.
        // Only do full pipeline analysis on grep-positive files.
        // Clean files get a lightweight record with zero findings.
        //
        // Priority order:
        //   1. Pre-computed suspicious list from the shell wrapper (--suspicious-list)
        //   2. PHP internal grep (when exec() is available)
        //   3. Scan all files (fallback)
        $suspiciousPatterns = [
            'eval\s*\(', 'base64_decode', 'gzinflate', 'gzdecode', 'gzuncompress',
            'str_rot13', 'shell_exec', 'system\s*\(', 'exec\s*\(', 'passthru',
            'proc_open', 'assert\s*\(', 'create_function',
            'togel', 'slot\s*online', 'casino', 'judi', 'viagra', 'cialis',
            'masuk-surga', 'display\s*:\s*none',
            'file_put_contents', 'move_uploaded_file',
            '\$_POST\[', '\$_GET\[', '\$_REQUEST\[',
        ];

        $suspiciousFiles = null;

        $shellFilterRendered = $this->suspiciousListPath !== null;

        if ($discoveredTotal === 0) {
            $suspiciousFiles = [];
        } else {
            if (!$shellFilterRendered) {
                $this->progress?->beginPatternFiltering();
            }

            if ($this->suspiciousListPath !== null && is_readable($this->suspiciousListPath)) {
                $susRaw          = file_get_contents($this->suspiciousListPath);
                $suspiciousFiles = array_values(array_filter(array_map('trim', explode("\n", $susRaw ?: ''))));
            } elseif (SystemTools::isGrepAvailable() && $discoveredTotal > 20) {
                $suspiciousFiles = SystemTools::grepFiles($files, $suspiciousPatterns);
                if ($suspiciousFiles === null) {
                    $suspiciousFiles = $files;
                }
            } else {
                $suspiciousFiles = $files;
            }

            $suspiciousFiles = $this->restrictFilesToTargetScope($suspiciousFiles ?? []);

            if (!$shellFilterRendered) {
                $this->progress?->completePatternFiltering(count($suspiciousFiles ?? $files), $discoveredTotal);
            }
        }

        $suspiciousSet = array_flip($suspiciousFiles ?? $files);

        // ── WordPress core integrity check ────────────────────────────────────
        // Check WP core files against the WordPress.org checksums API.
        // Result is stored as slug='core' in pluginIntegrityResults so it flows
        // through the same reporting and skip-filtering path as plugins.
        if ($this->shouldRunCoreIntegrity()) {
            $wpRoot = $this->resolveCoreIntegrityRoot();
            if ($wpRoot !== null) {
                $this->verifiedCoreRoot = $this->normalizePath($wpRoot);
                $this->progress?->beginCoreIntegrity();
                $coreIntegrity = $this->coreChecker->check($wpRoot);
                $this->progress?->finishCoreIntegrity();
                $this->pluginIntegrityResults['core'] = $coreIntegrity;
                $this->emit($this->formatIntegrityLine('core', $coreIntegrity));
            }
        }

        // ── Plugin integrity pre-check ────────────────────────────────────────
        // Run integrity checks only for plugin-scoped targets.
        if ($this->shouldRunPluginIntegrity()) {
            $pluginTargets = $this->discoverPluginIntegrityTargets($files);
            $this->preCheckPluginIntegrity($pluginTargets);
        }

        // ── Generate integrity findings ───────────────────────────────────────
        $integrityFindingsByFile = $this->generateIntegrityFindings();

        // ── Smart candidate selection ─────────────────────────────────────────
        // In smart mode, deep-scan only files that still need malware analysis
        // after integrity results are known. Fully verified official files are
        // skipped; modified or unexpected local files remain analyzable.
        $savedCount = 0;
        if (!$this->config->fullMode) {
            $selection = $this->selectMalwareAnalysisFiles($files, $suspiciousFiles ?? $files);
            $files = $selection['files'];
            $savedCount = $selection['integritySkippedCount'];
            if ($savedCount > 0) {
                $this->emit("  Skipped {$savedCount} unchanged official file(s) after integrity analysis (use --full to override)\n");
            }
        }

        // ── Quick mode: integrity-only, skip deep malware scan ────────────────
        if ($this->config->quickMode) {
            $rawResults = [];
            $this->injectExtraFindings($rawResults, $integrityFindingsByFile);
            if ($this->shouldRunUploadsAnomalyScan()) {
                $uploadsFindingsByFile = $this->scanUploadsAnomalies();
                $this->injectExtraFindings($rawResults, $uploadsFindingsByFile);
                if ($uploadsFindingsByFile !== []) {
                    $this->aggregateCleanUpld001InRawResults($rawResults);
                }
            }
            $resultsWithFindings = array_filter($rawResults, fn($r) => !empty($r['findings']));
            $fileResults         = $this->riskEngine->scoreAndSortFileResults(array_values($resultsWithFindings));
            return new \Wpma\Models\ScanReport(
                scanId:           uniqid('wpma-', true),
                target:           $this->config->target,
                startedAt:        $startedAt,
                completedAt:      new \DateTimeImmutable(),
                durationMs:       round((microtime(true) * 1000) - $startMs, 2),
                filesScanned:     0,
                filesSkipped:     $savedCount,
                fileResults:      $fileResults,
                allIocs:          [],
                correlations:     [],
                warnings:         $warnings,
                overallRiskScore: $this->riskEngine->computeOverallScore($fileResults),
                pluginIntegrity:  $this->serializeIntegrityResults(),
            );
        }

        $analysisTotal = count($files);

        if ($this->config->fullMode) {
            $this->emit("  Full malware analysis enabled. This may take several minutes depending on the number of files...\n");
        }

        if (!$this->config->quickMode) {
            $this->progress?->beginMalwareAnalysis();
        }

        // ── Main scan loop ────────────────────────────────────────────────────
        foreach ($files as $filePath) {
            $done++;

            if ($onProgress !== null) {
                $onProgress($done, $analysisTotal, $filePath);
            }

            // Full pipeline analysis
            $ao       = $this->pipeline->run($filePath, $this->config->target);

            // ── Plugin integrity check ────────────────────────────────────────
            // Detect if this file lives inside a WP plugin directory and check integrity
            $pluginIntegrity = $this->shouldRunPluginIntegrity()
                ? $this->resolvePluginIntegrity($filePath)
                : null;

            $findings = [];

            foreach ($this->detectors as $detector) {
                if (!$detector->isApplicable($ao)) {
                    continue;
                }
                try {
                    $detected = $detector->detect($ao);

                    foreach ($detected as $f) {
                        if (!$f->severity->isAtLeast($this->config->minSeverity)) {
                            continue;
                        }
                        // Apply plugin integrity confidence adjustment
                        if ($pluginIntegrity !== null) {
                            $f = $this->adjustFindingForIntegrity($f, $pluginIntegrity);
                            if ($f === null) {
                                continue; // suppressed by integrity check
                            }
                        }
                        $findings[] = $f;
                    }
                } catch (\Throwable $e) {
                    $warnings[] = new ScanWarning(
                        message:     sprintf('[%s] %s', $detector->getName(), $e->getMessage()),
                        filePath:    $filePath,
                        warningType: 'detector_error',
                    );
                }
            }

            foreach ($ao->iocs as $ioc) {
                $allIocs[] = $ioc;
            }

            foreach ($ao->parseErrors as $err) {
                if (!empty($err->message)) {
                    $warnings[] = new ScanWarning(
                        message:     $err->message,
                        filePath:    $filePath,
                        warningType: 'parse_error',
                    );
                }
            }

            $rawResults[] = [
                'filePath'     => $filePath,
                'relativePath' => $ao->meta->relativePath,
                'findings'     => $findings,
                'iocs'         => $ao->iocs,
                'wpContext'    => $ao->meta->wpContext,
                'scanTimeMs'   => $ao->meta->scanTimeMs,
            ];
        }

        // ── Uploads anomaly scan ──────────────────────────────────────────────
        // Independently enumerate wp-content/uploads/ for non-media files.
        // Skipped when --no-uploads is passed.
        $uploadsFindingsByFile = $this->shouldRunUploadsAnomalyScan()
            ? $this->scanUploadsAnomalies()
            : [];

        // ── Inject integrity + uploads findings ───────────────────────────────
        // Files not in the suspicious set (non-PHP, extensionless, archives) get
        // their own rawResult entries here so they appear in the final report.
        $this->injectExtraFindings($rawResults, $integrityFindingsByFile);
        $this->injectExtraFindings($rawResults, $uploadsFindingsByFile);

        // ── Aggregate clean UPLD-001 findings ─────────────────────────────────
        // After all findings (behavioral + uploads anomaly) have been merged into
        // $rawResults, collapse clean UPLD-001-only files (≥4) into one summary.
        // Must run after injectExtraFindings so behavioral co-findings on the
        // same file are visible and excluded from the clean set.
        if ($uploadsFindingsByFile !== []) {
            $this->aggregateCleanUpld001InRawResults($rawResults);
        }

        // ── Score and build report ────────────────────────────────────────────
        // Only pass files with findings to the risk engine to keep report clean
        $resultsWithFindings = array_filter(
            $rawResults,
            fn($r) => !empty($r['findings'])
        );

        $fileResults  = $this->riskEngine->scoreAndSortFileResults(array_values($resultsWithFindings));
        $overallScore = $this->riskEngine->computeOverallScore($fileResults);
        $completedAt  = new \DateTimeImmutable();
        $durationMs   = (microtime(true) * 1000) - $startMs;

        // Deduplicate IOCs
        $seenIoc     = [];
        $dedupedIocs = [];
        foreach ($allIocs as $ioc) {
            $key = $ioc->type->value . ':' . $ioc->value;
            if (!isset($seenIoc[$key])) {
                $seenIoc[$key] = true;
                $dedupedIocs[] = $ioc;
            }
        }

        return new ScanReport(
            scanId:           uniqid('wpma-', true),
            target:           $this->config->target,
            startedAt:        $startedAt,
            completedAt:      $completedAt,
            durationMs:       round($durationMs, 2),
            filesScanned:     $done,
            filesSkipped:     $skipped,
            fileResults:      $fileResults,
            allIocs:          $dedupedIocs,
            correlations:     [],
            warnings:         $warnings,
            overallRiskScore: $overallScore,
            pluginIntegrity:  $this->serializeIntegrityResults(),
        );
    }

    private function generateIntegrityFindings(): array
    {
        $detector        = new PluginIntegrityDetector();
        $findingsByFile  = [];

        foreach ($this->pluginIntegrityResults as $slug => $integrity) {
            if ($integrity->isUnavailable()) {
                continue;
            }

            // Resolve the plugin directory from what we know
            $pluginDir = $this->resolvePluginDirForSlug($slug);
            if ($pluginDir === '') {
                continue;
            }

            $findings = $detector->generateFindings($integrity, $pluginDir);

            foreach ($findings as $finding) {
                $key = $finding->filePath;
                if (!isset($findingsByFile[$key])) {
                    $findingsByFile[$key] = [];
                }
                $findingsByFile[$key][] = $finding;
            }
        }

        return $findingsByFile;
    }

    /**
     * Resolve the absolute plugin directory for a slug we have already checked.
     * We stored the plugin dir during preCheckPluginIntegrity — reconstruct it here.
     */
    private function resolvePluginDirForSlug(string $slug): string
    {
        if (isset($this->pluginIntegrityTargets[$slug]['pluginDir'])) {
            return $this->normalizePath($this->pluginIntegrityTargets[$slug]['pluginDir']);
        }

        $scanRoot = rtrim(str_replace('\\', '/', $this->config->target), '/');

        if ($this->config->targetType === ScanTargetType::SINGLE_PLUGIN
            && basename($scanRoot) === $slug
            && is_dir($scanRoot)
        ) {
            return $scanRoot;
        }

        if ($this->config->targetType === ScanTargetType::PLUGINS_DIRECTORY) {
            $candidate = $scanRoot . '/' . $slug;
            if (is_dir($candidate)) {
                return $candidate;
            }
        }

        if ($this->config->targetType === ScanTargetType::WORDPRESS_SITE) {
            $candidate = $scanRoot . '/wp-content/plugins/' . $slug;
            if (is_dir($candidate)) {
                return $candidate;
            }
        }

        return '';
    }

    /**
     * @param array<string, array{pluginDir: string, wpRoot: string}> $pluginTargets
     */
    private function preCheckPluginIntegrity(array $pluginTargets): void
    {
        $this->pluginIntegrityTargets = $pluginTargets;

        $total = count($pluginTargets);
        if ($total === 0) {
            $this->progress?->beginPluginIntegrity();
            $this->progress?->completePluginIntegrity(0);
            return;
        }

        $this->progress?->beginPluginIntegrity();

        $current = 0;
        foreach ($pluginTargets as $slug => $target) {
            $current++;
            $this->progress?->beginPluginCheck($current, $total, $slug);
            $integrity = $this->integrityChecker->check($target['pluginDir'], $target['wpRoot']);
            $this->progress?->finishPluginCheck();
            $this->pluginIntegrityResults[$slug] = $integrity;
            $this->emit($this->formatIntegrityLine($slug, $integrity, $current, $total));
        }

        $this->progress?->completePluginIntegrity($total);
    }

    /**
     * @param string[] $files
     * @return array<string, array{pluginDir: string, wpRoot: string}>
     */
    private function discoverPluginIntegrityTargets(array $files): array
    {
        $targets = [];
        $scanRoot = rtrim(str_replace('\\', '/', $this->config->target), '/');

        if ($this->config->targetType === ScanTargetType::SINGLE_PLUGIN && is_dir($scanRoot)) {
            $targets[basename($scanRoot)] = [
                'pluginDir' => $scanRoot,
                'wpRoot'    => dirname($scanRoot, 3),
            ];

            return $targets;
        }

        foreach ($files as $filePath) {
            $path = rtrim(str_replace('\\', '/', $filePath), '/');
            if (!preg_match('#/wp-content/plugins/([^/]+)/#', $path, $m)) {
                continue;
            }

            $slug = $m[1];
            if (isset($targets[$slug])) {
                continue;
            }

            $targets[$slug] = [
                'pluginDir' => preg_replace('#(/wp-content/plugins/' . preg_quote($slug, '#') . ').*$#', '$1', $path),
                'wpRoot'    => preg_replace('#/wp-content.*$#', '', $path),
            ];
        }

        return $targets;
    }

    private function serializeIntegrityResults(): array
    {
        $out = [];
        foreach ($this->pluginIntegrityResults as $slug => $integrity) {
            $skippedMalwareAnalysis = isset($this->malwareAnalysisSkippedPlugins[$slug]);
            $out[$slug] = [
                'status'                  => $integrity->status,
                'version'                 => $integrity->version,
                'method'                  => $integrity->method,
                'officialCount'           => $integrity->officialCount,
                'localCount'              => $integrity->localCount,
                'okCount'                 => $integrity->okCount,
                'modifiedFiles'           => $integrity->modifiedFiles,
                'unexpectedFiles'         => $integrity->unexpectedFiles,
                'missingFiles'            => $integrity->missingFiles,
                'officialSourceAvailable' => !$integrity->isUnavailable(),
                'malwareAnalysisSkipped'  => $skippedMalwareAnalysis,
            ];
        }
        return $out;
    }

    /**
     * Detect the WordPress installation root from the scan target.
     * Walks up the directory tree looking for wp-config.php.
     */
    private function detectWpRoot(): ?string
    {
        $target = rtrim(str_replace('\\', '/', $this->config->target), '/');

        if (is_file($target . '/wp-config.php')) {
            return $target;
        }

        for ($depth = 1; $depth <= 5; $depth++) {
            $parent = dirname($target, $depth);
            if ($parent === $target) {
                break;
            }
            if (is_file($parent . '/wp-config.php')) {
                return $parent;
            }
        }

        return null;
    }

    /**
     * Build the smart-mode malware analysis candidate list.
     *
     * Start from grep-selected suspicious files, then refine with integrity data:
     * - VERIFIED components: remove all local files from analysis
     * - MODIFIED components: analyze only local modified/unexpected files
     * - UNAVAILABLE/CHECKSUM_UNAVAILABLE components: keep grep-selected files
     *
     * @param string[] $files
     * @param string[] $suspiciousFiles
     * @return array{files: list<string>, integritySkippedCount: int}
     */
    private function selectMalwareAnalysisFiles(array $files, array $suspiciousFiles): array
    {
        $discovered = [];
        foreach ($files as $file) {
            $discovered[$this->normalizePath($file)] = $file;
        }

        $selected = [];
        foreach ($suspiciousFiles as $file) {
            $norm = $this->normalizePath($file);
            if (isset($discovered[$norm])) {
                $selected[$norm] = true;
            }
        }

        $initialSelected = $selected;

        foreach ($this->pluginIntegrityResults as $slug => $integrity) {
            if ($slug === 'core') {
                $wpRoot = $this->verifiedCoreRoot ?? $this->resolveCoreIntegrityRoot();
                if ($wpRoot === null) {
                    continue;
                }

                $wpRoot = $this->normalizePath($wpRoot);
                $this->applyCoreIntegritySelection($selected, $discovered, $integrity, $wpRoot);
                continue;
            }

            $componentDir = $this->resolvePluginDirForSlug($slug);
            if ($componentDir === '') {
                continue;
            }

            if ($integrity->isUnavailable()) {
                if ($this->shouldSkipBehavioralAnalysisForUnavailablePlugin()) {
                    $this->removePrefixedFilesFromSelection($selected, $componentDir);
                    $this->malwareAnalysisSkippedPlugins[$slug] = true;
                }
                continue;
            }

            $this->removePrefixedFilesFromSelection($selected, $componentDir);
            foreach ($this->localIntegrityAnomalyPaths($integrity, $componentDir) as $path) {
                if (isset($discovered[$path])) {
                    $selected[$path] = true;
                }
            }
        }

        $integritySkippedCount = count(array_diff_key($initialSelected, $selected));

        return [
            'files' => array_values(array_filter(
                $files,
                fn (string $file): bool => isset($selected[$this->normalizePath($file)])
            )),
            'integritySkippedCount' => $integritySkippedCount,
        ];
    }

    /**
     * @return list<string>
     */
    private function localIntegrityAnomalyPaths(PluginIntegrity $integrity, string $componentRoot): array
    {
        $paths = [];
        foreach (array_merge($integrity->modifiedFiles, $integrity->unexpectedFiles) as $relPath) {
            $paths[] = $this->normalizePath(
                rtrim($componentRoot, '/\\') . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relPath)
            );
        }

        return array_values(array_unique($paths));
    }

    /** @param array<string, true> $selected */
    private function removePrefixedFilesFromSelection(array &$selected, string $componentRoot): void
    {
        $prefix = rtrim($this->normalizePath($componentRoot), '/') . '/';
        foreach (array_keys($selected) as $path) {
            if (str_starts_with($path, $prefix)) {
                unset($selected[$path]);
            }
        }
    }

    /**
     * @param array<string, true>   $selected
     * @param array<string, string> $discovered
     */
    private function applyCoreIntegritySelection(
        array &$selected,
        array $discovered,
        PluginIntegrity $integrity,
        string $wpRoot,
    ): void {
        $verified = array_fill_keys(
            array_map(fn (string $path): string => $this->canonicalRelativePath($path), $integrity->verifiedFiles),
            true,
        );

        foreach (array_keys($selected) as $path) {
            $relative = $this->canonicalRelativePath($path, $wpRoot);
            if (isset($verified[$relative])) {
                unset($selected[$path]);
            }
        }

        foreach ($this->localIntegrityAnomalyPaths($integrity, $wpRoot) as $path) {
            if (isset($discovered[$path])) {
                $selected[$path] = true;
            }
        }
    }

    /**
     * @param string[] $files
     * @return string[]
     */
    private function restrictFilesToTargetScope(array $files): array
    {
        if ($this->config->targetType !== ScanTargetType::WORDPRESS_CORE || $files === []) {
            return $files;
        }

        $wpRoot = $this->resolveCoreIntegrityRoot();
        if ($wpRoot === null) {
            return $files;
        }

        $wpRoot = $this->normalizePath($wpRoot);

        return array_values(array_filter(
            $files,
            fn (string $file): bool => $this->isCoreRelativePath($this->canonicalRelativePath($file, $wpRoot))
        ));
    }

    private function isCoreRelativePath(string $path): bool
    {
        foreach (['wp-admin', 'wp-includes'] as $dir) {
            if (str_starts_with($path, $dir . '/')) {
                return true;
            }
        }

        return in_array($path, self::CORE_ROOT_FILES, true);
    }

    private function canonicalRelativePath(string $path, ?string $root = null): string
    {
        $normalized = $this->normalizePath($path);

        if ($root !== null && $root !== '') {
            $root = rtrim($this->normalizePath($root), '/');
            if ($normalized === $root) {
                return '';
            }
            if (str_starts_with($normalized, $root . '/')) {
                $normalized = substr($normalized, strlen($root) + 1);
            }
        }

        while (str_starts_with($normalized, './')) {
            $normalized = substr($normalized, 2);
        }

        return ltrim($normalized, '/');
    }

    private function normalizePath(string $path): string
    {
        $normalized = str_replace('\\', '/', $path);
        $normalized = preg_replace('#/+#', '/', $normalized) ?? $normalized;

        if (preg_match('#^/([a-zA-Z])/(.*)$#', $normalized, $m)) {
            $normalized = strtoupper($m[1]) . ':/' . $m[2];
        } elseif (preg_match('#^([a-zA-Z]):/(.*)$#', $normalized, $m)) {
            $normalized = strtoupper($m[1]) . ':/' . $m[2];
        }

        return rtrim($normalized, '/');
    }

    /**
     * Write a progress line to STDERR when showProgress is enabled.
     */
    private function emit(string $message): void
    {
        if ($this->config->showProgress) {
            fwrite(STDERR, $message);
        }
    }

    /**
     * Format a single integrity result line for progress output.
     */
    private function formatIntegrityLine(string $slug, \Wpma\WP\PluginIntegrity $integrity, ?int $current = null, ?int $total = null): string
    {
        $version = $integrity->version !== '' ? " v{$integrity->version}" : '';

        if ($integrity->isUnavailable()) {
            if ($integrity->status === \Wpma\WP\PluginIntegrity::CHECKSUM_UNAVAILABLE) {
                $status = $this->formatStatus('? API unreachable', 'yellow');
            } elseif ($this->shouldSkipBehavioralAnalysisForUnavailablePlugin()) {
                $status = $this->formatStatus('⚠ Unverified [premium/custom]  Official WordPress.org release: Not available  Malware analysis: Skipped', 'yellow');
            } else {
                $status = $this->formatStatus('⚠ Unverified [premium/custom]  Official WordPress.org release: Not available', 'yellow');
            }
        } elseif ($integrity->isVerified()) {
            $status = $this->formatStatus('✔ verified', 'green');
            if ($integrity->officialCount > 0) {
                $status .= "  ({$integrity->okCount}/{$integrity->officialCount} files OK)";
            }
        } else {
            $extra    = count($integrity->unexpectedFiles);
            $modified = count($integrity->modifiedFiles);
            $missing  = count($integrity->missingFiles);
            $parts    = [];
            if ($extra > 0) {
                $parts[] = "{$extra} extra";
            }
            if ($modified > 0) {
                $parts[] = "{$modified} modified";
            }
            if ($missing > 0) {
                $parts[] = "{$missing} missing";
            }
            $status = $this->formatStatus('✘ MODIFIED', 'red') . '  ' . implode(', ', $parts);
        }

        $prefix = '';
        if ($current !== null && $total !== null && $total > 1) {
            $prefix = sprintf('[%d/%d] ', $current, $total);
        }

        return sprintf("  %-40s %s%s\n", $prefix . $slug, $status, $version);
    }

    private function formatStatus(string $label, string $color): string
    {
        if ($this->config->noColor) {
            return $label;
        }

        $code = match ($color) {
            'green' => '32',
            'yellow' => '33',
            'red' => '31',
            default => '0',
        };

        return sprintf("\033[%sm%s\033[0m", $code, $label);
    }

    private function relativePath(string $filePath): string
    {
        $root = str_replace('\\', '/', $this->config->target);
        $path = str_replace('\\', '/', $filePath);
        return ltrim(str_replace($root, '', $path), '/');
    }

    private function shouldRunCoreIntegrity(): bool
    {
        return $this->config->checkCore
            && in_array($this->config->targetType, [ScanTargetType::WORDPRESS_SITE, ScanTargetType::WORDPRESS_CORE], true);
    }

    private function shouldRunPluginIntegrity(): bool
    {
        return in_array(
            $this->config->targetType,
            [ScanTargetType::WORDPRESS_SITE, ScanTargetType::PLUGINS_DIRECTORY, ScanTargetType::SINGLE_PLUGIN],
            true
        );
    }

    private function shouldRunUploadsAnomalyScan(): bool
    {
        return $this->config->checkUploads
            && in_array($this->config->targetType, [ScanTargetType::WORDPRESS_SITE, ScanTargetType::UPLOADS_DIRECTORY], true);
    }

    private function shouldSkipBehavioralAnalysisForUnavailablePlugin(): bool
    {
        return in_array(
            $this->config->targetType,
            [ScanTargetType::WORDPRESS_SITE, ScanTargetType::PLUGINS_DIRECTORY],
            true
        );
    }

    private function resolveCoreIntegrityRoot(): ?string
    {
        if ($this->config->targetType === ScanTargetType::WORDPRESS_CORE) {
            $target = rtrim(str_replace('\\', '/', $this->config->target), '/');
            $base   = basename($target);

            if (in_array($base, ['wp-admin', 'wp-includes'], true)) {
                return dirname($target);
            }

            return $target;
        }

        return $this->detectWpRoot();
    }

    // ── Uploads anomaly scanning ─────────────────────────────────────────

    /**
     * Locate the uploads directory within the current scan scope and run
     * UploadsAnomalyScanner on it.
     *
     * Handles three targeting modes:
     *   1. Full WP site scan  : target/wp-content/uploads/
     *   2. Uploads dir scan   : target IS wp-content/uploads (or a subdir)
     *   3. Plugin / other dir : no uploads detected → returns []
     *
     * @return array<string, \Wpma\Models\Finding[]>
     */
    private function scanUploadsAnomalies(): array
    {
        $scanRoot   = rtrim(str_replace('\\', '/', $this->config->target), '/');
        $uploadsDir = null;

        // Case 1: scanning a full WP site — uploads is one level down
        $candidate = $scanRoot . '/wp-content/uploads';
        if (is_dir($candidate)) {
            $uploadsDir = $candidate;
        }

        // Case 2: the scan root IS the uploads directory (or a subdirectory of it)
        if ($uploadsDir === null && preg_match('#wp-content/uploads#i', $scanRoot) && is_dir($scanRoot)) {
            $uploadsDir = $scanRoot;
        }

        if ($uploadsDir === null) {
            return [];
        }

        $scanner = new UploadsAnomalyScanner();
        return $scanner->scan($uploadsDir);
    }

    /**
     * Aggregate clean UPLD-001 findings in $rawResults after all findings have
     * been merged (behavioral + uploads anomaly).
     *
     * Must be called AFTER both injectExtraFindings() calls so that co-located
     * behavioral findings (e.g. BACK-001 on a malicious PHP in uploads) are
     * already present in the same rawResult entry and therefore prevent that
     * file from being included in the clean aggregate.
     *
     * @param array<int, array> $rawResults  Passed by reference
     */
    private function aggregateCleanUpld001InRawResults(array &$rawResults): void
    {
        // Determine the uploads directory from the scan configuration
        $scanRoot   = rtrim(str_replace('\\', '/', $this->config->target), '/');
        $uploadsDir = null;

        $candidate = $scanRoot . '/wp-content/uploads';
        if (is_dir($candidate)) {
            $uploadsDir = $candidate;
        }

        if ($uploadsDir === null && preg_match('#wp-content/uploads#i', $scanRoot) && is_dir($scanRoot)) {
            $uploadsDir = $scanRoot;
        }

        if ($uploadsDir === null) {
            return;
        }

        $uploadsDir = rtrim(str_replace('\\', '/', $uploadsDir), '/');

        // ── Identify clean UPLD-001 entries ──────────────────────────────────
        // A "clean" entry is one where:
        //   • every finding has ruleId === 'UPLD-001'
        //   • the file lives inside the uploads directory
        $cleanIndexes    = []; // indexes into $rawResults of clean-only entries
        $cleanAbsPaths   = []; // absolute paths of clean entries

        foreach ($rawResults as $idx => $entry) {
            $absPath = str_replace('\\', '/', $entry['filePath']);

            // Only consider files inside uploads
            if (!str_starts_with($absPath, $uploadsDir . '/')) {
                continue;
            }

            // Must have at least one finding and all must be UPLD-001
            if (empty($entry['findings'])) {
                continue;
            }

            $hasOnlyUpld001 = true;
            foreach ($entry['findings'] as $finding) {
                if ($finding->ruleId !== 'UPLD-001') {
                    $hasOnlyUpld001 = false;
                    break;
                }
            }

            if ($hasOnlyUpld001) {
                $cleanIndexes[]  = $idx;
                $cleanAbsPaths[] = $absPath;
            }
        }

        // Below threshold: nothing to do
        if (count($cleanAbsPaths) < UploadsAnomalyScanner::UPLD001_AGGREGATE_THRESHOLD) {
            return;
        }

        // Sort for deterministic representative path selection
        sort($cleanAbsPaths);
        sort($cleanIndexes);

        // Remove the individual clean entries from rawResults
        foreach ($cleanIndexes as $idx) {
            unset($rawResults[$idx]);
        }

        // Compute relative paths for display
        $relPaths = array_map(
            static fn(string $p): string => ltrim(substr($p, strlen($uploadsDir)), '/'),
            $cleanAbsPaths,
        );

        // Build the aggregate and inject it
        $scanner      = new UploadsAnomalyScanner();
        $virtualPath  = $uploadsDir . '/__upld001_aggregate__';

        $aggregateFindings = [
            $scanner->makeAggregateUpld001Finding(
                $virtualPath,
                $uploadsDir,
                count($cleanAbsPaths),
                $cleanAbsPaths,
                $relPaths,
            ),
        ];

        $rawResults[] = [
            'filePath'     => $virtualPath,
            'relativePath' => $this->relativePath($virtualPath),
            'findings'     => $aggregateFindings,
            'iocs'         => [],
            'wpContext'    => null,
            'scanTimeMs'   => 0.0,
        ];

        // Re-index to avoid gaps
        $rawResults = array_values($rawResults);
    }

    /**
     * Inject extra findings (from integrity or uploads scanner) into $rawResults.
     *
     * If a rawResult entry already exists for the file (e.g. a PHP file that was
     * also detected by the main scan loop), the findings are merged into it.
     * Otherwise a new entry is created so the file appears in the final report.
     *
     * @param array<int, array>          $rawResults      Passed by reference
     * @param array<string, \Wpma\Models\Finding[]> $findingsByFile
     */
    private function injectExtraFindings(array &$rawResults, array $findingsByFile): void
    {
        foreach ($findingsByFile as $absPath => $findings) {
            $found = false;

            foreach ($rawResults as &$existing) {
                $normExisting = str_replace('\\', '/', $existing['filePath']);
                $normAbs      = str_replace('\\', '/', $absPath);
                if ($normExisting === $normAbs) {
                    $existing['findings'] = array_merge($existing['findings'], $findings);
                    $found = true;
                    break;
                }
            }
            unset($existing);

            if (!$found) {
                $rawResults[] = [
                    'filePath'     => $absPath,
                    'relativePath' => $this->relativePath($absPath),
                    'findings'     => $findings,
                    'iocs'         => [],
                    'wpContext'    => null,
                    'scanTimeMs'   => 0.0,
                ];
            }
        }
    }

    /**
     * Detect if a file lives inside a WP plugin directory and return its integrity.
     * Caches per plugin slug so the API is only called once per plugin.
     */
    private function resolvePluginIntegrity(string $filePath): ?PluginIntegrity
    {
        if (!$this->shouldRunPluginIntegrity()) {
            return null;
        }

        $path = str_replace('\\', '/', $filePath);

        if (preg_match('#/wp-content/plugins/([^/]+)/#', $path, $m)) {
            $slug      = $m[1];
            $pluginDir = preg_replace('#(/wp-content/plugins/' . preg_quote($slug, '#') . ').*$#', '$1', $path);
        } elseif ($this->config->targetType === ScanTargetType::SINGLE_PLUGIN) {
            $scanRoot = rtrim(str_replace('\\', '/', $this->config->target), '/');
            if (!str_starts_with($path, $scanRoot)) {
                return null;
            }
            $slug      = basename($scanRoot);
            $pluginDir = $scanRoot;
        } else {
            return null;
        }

        if (isset($this->pluginIntegrityResults[$slug])) {
            return $this->pluginIntegrityResults[$slug];
        }

        $integrity = $this->integrityChecker->check($pluginDir, dirname($pluginDir, 3));
        $this->pluginIntegrityResults[$slug] = $integrity;

        return $integrity;
    }

    /**
     * Adjust a finding's confidence/severity based on plugin integrity.
     *
     * Rules:
     * - NEVER suppress eval(), remote loaders, filesystem writes, obfuscation
     * - Verified plugin: reduce confidence on common WP patterns (call_user_func etc.)
     * - Modified plugin: increase confidence on all suspicious findings
     *
     * Returns null only if the finding should be suppressed entirely.
     * Returns the (possibly modified) Finding otherwise.
     */
    private function adjustFindingForIntegrity(
        \Wpma\Models\Finding   $finding,
        PluginIntegrity        $integrity,
    ): ?\Wpma\Models\Finding {
        // These rule IDs are NEVER adjusted — always critical threats
        $neverAdjust = ['BACK-003', 'SEO-006', 'SEO-007', 'BACK-002'];
        if (\in_array($finding->ruleId, $neverAdjust, true)) {
            return $finding;
        }

        // Never suppress CRITICAL severity regardless of integrity
        if ($finding->severity === \Wpma\Models\Severity::CRITICAL) {
            return $finding;
        }

        if ($integrity->isVerified()) {
            // Verified plugin: downgrade confidence on LOW/MEDIUM findings
            // with WP-standard function patterns
            $wpStandardRules = ['BACK-001', 'BACK-004'];
            if (\in_array($finding->ruleId, $wpStandardRules, true)) {
                if ($finding->severity === \Wpma\Models\Severity::LOW) {
                    return null; // Suppress LOW findings in verified plugins
                }
                // Downgrade MEDIUM → LOW for verified plugins
                if ($finding->severity === \Wpma\Models\Severity::MEDIUM) {
                    return \Wpma\Models\Finding::create(array_merge($finding->toArray(), [
                        'severity'    => \Wpma\Models\Severity::LOW,
                        'confidence'  => \Wpma\Models\Confidence::LOW,
                        'explanation' => $finding->explanation . ' [Plugin verified against WordPress.org checksums — reduced confidence]',
                        'tags'        => array_merge($finding->tags, ['integrity-verified']),
                    ]));
                }
            }
        }

        if ($integrity->isModified()) {
            // Modified plugin: add a note to all findings in modified files
            $isModifiedFile = false;
            $relPath = $this->relativePath($finding->filePath);
            foreach ($integrity->modifiedFiles as $mf) {
                if (str_ends_with($relPath, $mf) || str_ends_with($mf, basename($relPath))) {
                    $isModifiedFile = true;
                    break;
                }
            }

            if ($isModifiedFile) {
                return \Wpma\Models\Finding::create(array_merge($finding->toArray(), [
                    'explanation' => $finding->explanation . ' [⚠ This file was MODIFIED from the official WordPress.org release — higher confidence this is injected code]',
                    'tags'        => array_merge($finding->tags, ['integrity-modified', 'modified-file']),
                ]));
            }
        }

        return $finding;
    }
}
