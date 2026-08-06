<?php

declare(strict_types=1);

namespace Wpma\Detectors;

use Wpma\Models\AnalysisObject;
use Wpma\Models\Confidence;
use Wpma\Models\DetectionCategory;
use Wpma\Models\Finding;
use Wpma\Models\Severity;
use Wpma\WP\PluginIntegrity;

/**
 * PluginIntegrityDetector — converts integrity check results (EXTRA, MODIFIED, MISSING)
 * into Finding objects so they appear in the standard scan report.
 *
 * This detector is NOT called through the normal detector dispatch loop.
 * It is called directly by ScanOrchestrator after the integrity pre-check,
 * once per plugin slug, and its findings are injected into the relevant FileResult.
 *
 * Design rules:
 *   - EXTRA files always generate a finding regardless of extension.
 *   - MODIFIED files generate a finding.
 *   - MISSING files generate an informational finding.
 *   - The severity and confidence depend on the file type and context.
 */
class PluginIntegrityDetector
{
    /**
     * Generate integrity findings for a single plugin.
     *
     * @param  PluginIntegrity $integrity  Result from PluginIntegrityChecker
     * @param  string          $pluginDir  Absolute path to the plugin directory
     * @return Finding[]
     */
    public function generateFindings(PluginIntegrity $integrity, string $pluginDir): array
    {
        if ($integrity->isUnavailable()) {
            return [];
        }

        $findings = [];
        $slug     = $integrity->slug;

        // ── EXTRA / UNEXPECTED files ──────────────────────────────────────────
        foreach ($integrity->unexpectedFiles as $relPath) {
            $absPath  = rtrim($pluginDir, '/\\') . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relPath);
            $severity = $this->extraFileSeverity($relPath, $absPath);
            $findings[] = $this->makeExtraFinding($slug, $relPath, $absPath, $severity);
        }

        // ── MODIFIED files ────────────────────────────────────────────────────
        foreach ($integrity->modifiedFiles as $relPath) {
            $absPath  = rtrim($pluginDir, '/\\') . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relPath);
            $findings[] = $this->makeModifiedFinding($slug, $relPath, $absPath, $integrity->version);
        }

        // ── MISSING files (informational — could be intentionally removed) ───
        // Only generate findings for missing PHP files (missing images/CSS is not suspicious)
        foreach ($integrity->missingFiles as $relPath) {
            if ($this->isMissingFileSuspicious($relPath)) {
                $findings[] = $this->makeMissingFinding($slug, $relPath, $integrity->version);
            }
        }

        return $findings;
    }

    // ── Finding factories ─────────────────────────────────────────────────────

    private function makeExtraFinding(
        string $slug,
        string $relPath,
        string $absPath,
        Severity $severity,
    ): Finding {
        $fileType  = $this->classifyFileType($relPath, $absPath);
        $typeLabel = $fileType === 'archive'   ? 'unexpected archive'
                   : ($fileType === 'php'      ? 'unexpected PHP file'
                   : ($fileType === 'binary'   ? 'unexpected binary file'
                   : 'unexpected file'));

        $isMaliciousArchive = $fileType === 'archive';

        return Finding::create([
            'ruleId'      => 'INTG-001',
            'title'       => sprintf('Unexpected file in verified plugin: %s', $relPath),
            'filePath'    => $absPath,
            'line'        => 0,
            'severity'    => $severity,
            'confidence'  => Confidence::HIGH,
            'category'    => DetectionCategory::INTEGRITY,
            'description' => sprintf(
                'File "%s" exists in the installed "%s" plugin directory but is NOT present in the official WordPress.org release.',
                $relPath,
                $slug,
            ),
            'explanation' => sprintf(
                'The WordPress.org checksum manifest for %s does not include "%s". '
                . 'This is an %s that was added after the official release was published. '
                . '%s'
                . 'Attackers frequently place malware inside plugin directories using filenames that blend in with legitimate files, '
                . 'including extensionless files, log files, and archives. '
                . 'This file should be investigated before the plugin is trusted.',
                $slug,
                $relPath,
                $typeLabel,
                $isMaliciousArchive
                    ? 'Archives found unexpectedly inside plugin directories are a critical indicator — they are commonly used to smuggle obfuscated PHP payloads. '
                    : '',
            ),
            'remediation' => 'Inspect the file contents immediately. If it is not part of the official plugin, delete it and scan for other injected files. '
                           . 'Consider restoring the plugin from a clean copy from WordPress.org.',
            'evidence'    => [],
            'tags'        => ['integrity', 'extra-file', $fileType],
        ]);
    }

    private function makeModifiedFinding(
        string $slug,
        string $relPath,
        string $absPath,
        string $version,
    ): Finding {
        return Finding::create([
            'ruleId'      => 'INTG-002',
            'title'       => sprintf('Modified file in verified plugin: %s', $relPath),
            'filePath'    => $absPath,
            'line'        => 0,
            'severity'    => Severity::HIGH,
            'confidence'  => Confidence::HIGH,
            'category'    => DetectionCategory::INTEGRITY,
            'description' => sprintf(
                'File "%s" in the "%s" plugin (v%s) has a different SHA-256 hash than the official WordPress.org release.',
                $relPath,
                $slug,
                $version,
            ),
            'explanation' => sprintf(
                'The SHA-256 checksum of "%s" does not match the official WordPress.org checksum for %s v%s. '
                . 'This means the file has been changed since the official release was published. '
                . 'Legitimate plugin updates always go through WordPress.org and change the version number. '
                . 'An in-place modification without a version bump is a strong indicator of injected malware. '
                . 'Inspect the file diff and compare it against the official release.',
                $relPath,
                $slug,
                $version,
            ),
            'remediation' => sprintf(
                'Download the clean version of %s v%s from WordPress.org and compare "%s" against the official copy. '
                . 'If the differences are not expected (e.g. local configuration), restore the file from the clean release.',
                $slug,
                $version,
                $relPath,
            ),
            'evidence'    => [],
            'tags'        => ['integrity', 'modified-file'],
        ]);
    }

    private function makeMissingFinding(
        string $slug,
        string $relPath,
        string $version,
    ): Finding {
        return Finding::create([
            'ruleId'      => 'INTG-003',
            'title'       => sprintf('Missing official file from plugin: %s', $relPath),
            'filePath'    => $relPath,  // no absolute path since file doesn't exist
            'line'        => 0,
            'severity'    => Severity::INFORMATIONAL,
            'confidence'  => Confidence::MEDIUM,
            'category'    => DetectionCategory::INTEGRITY,
            'description' => sprintf(
                'File "%s" is present in the official WordPress.org release of "%s" v%s but is not found on disk.',
                $relPath,
                $slug,
                $version,
            ),
            'explanation' => 'A missing official file can indicate intentional deletion (e.g. stripping parts of the plugin), '
                           . 'or it may be the result of a partial installation. '
                           . 'This is informational; missing files are less likely to indicate active malware than extra or modified files.',
            'remediation' => 'Verify the plugin was installed completely. If files were intentionally removed, document the reason. '
                           . 'Otherwise, reinstall the plugin from WordPress.org.',
            'evidence'    => [],
            'tags'        => ['integrity', 'missing-file'],
        ]);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Determine severity of an EXTRA file based on its type and content.
     */
    private function extraFileSeverity(string $relPath, string $absPath): Severity
    {
        $type = $this->classifyFileType($relPath, $absPath);

        return match ($type) {
            'archive' => Severity::CRITICAL,   // unexpected archive = very suspicious
            'php'     => Severity::HIGH,        // unexpected PHP = suspicious
            'binary'  => Severity::HIGH,        // unexpected binary = suspicious
            default   => Severity::MEDIUM,      // unexpected anything else = medium
        };
    }

    /**
     * Classify a file by its actual content (not just extension).
     * This is important because attackers use extensionless files.
     */
    private function classifyFileType(string $relPath, string $absPath): string
    {
        $ext = strtolower(pathinfo($relPath, PATHINFO_EXTENSION));

        // Extension-based fast path for common safe types
        if (\in_array($ext, ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'ico'], true)) {
            return 'image';
        }
        if (\in_array($ext, ['css', 'scss', 'less'], true)) {
            return 'style';
        }
        if (\in_array($ext, ['js', 'ts', 'mjs'], true)) {
            return 'script';
        }
        if ($ext === 'php') {
            return 'php';
        }

        // For extensionless or unknown-extension files, read the first bytes
        if (!is_readable($absPath)) {
            return 'unknown';
        }

        $header = @file_get_contents($absPath, false, null, 0, 8);
        if ($header === false || $header === '') {
            return 'unknown';
        }

        // ZIP archive magic: PK\x03\x04
        if (str_starts_with($header, "PK\x03\x04")) {
            return 'archive';
        }
        // gzip magic: \x1f\x8b
        if (str_starts_with($header, "\x1f\x8b")) {
            return 'archive';
        }
        // RAR magic: Rar!
        if (str_starts_with($header, "Rar!")) {
            return 'archive';
        }
        // 7-zip magic: 7z\xbc\xaf\x27\x1c
        if (str_starts_with($header, "7z\xbc\xaf")) {
            return 'archive';
        }
        // PHP open tag
        if (str_starts_with($header, '<?php') || str_starts_with($header, '<?=')) {
            return 'php';
        }
        // ELF binary
        if (str_starts_with($header, "\x7fELF")) {
            return 'binary';
        }
        // PE binary (Windows .exe/.dll)
        if (str_starts_with($header, 'MZ')) {
            return 'binary';
        }

        return 'unknown';
    }

    /**
     * Only generate MISSING findings for PHP files — missing CSS/images are noise.
     */
    private function isMissingFileSuspicious(string $relPath): bool
    {
        $ext = strtolower(pathinfo($relPath, PATHINFO_EXTENSION));
        return $ext === 'php' || $ext === 'phtml' || $ext === '';
    }
}
