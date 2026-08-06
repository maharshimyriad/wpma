<?php

declare(strict_types=1);

namespace Wpma\Config;

use Wpma\Cli\ScanTargetType;
use Wpma\Models\OutputFormat;
use Wpma\Models\Severity;

/**
 * ScanConfig — immutable value object holding all scan-time configuration.
 *
 * All properties are set at construction time and cannot be changed afterwards,
 * making instances safe to share across threads/workers without locking.
 */
readonly class ScanConfig
{
    /**
     * @param string         $target              Filesystem path (file or directory) to scan.
     * @param OutputFormat   $outputFormat        Requested report format (text/json/html).
     * @param string|null    $outputFile          Optional file path to write the report to.
     * @param Severity       $minSeverity         Minimum severity level to include in the report.
     * @param bool           $noColor             Disable ANSI colour codes in text output.
     * @param int            $workers             Number of parallel worker processes.
     * @param int            $maxFileSizeBytes    Per-file size limit; files above this are skipped.
     * @param bool           $showProgress        Display a progress indicator during the scan.
     * @param bool           $quickMode           Integrity check only; skip the deep malware scan.
     * @param bool           $fullMode            Force deep scan every file even if integrity passes.
     * @param bool           $checkCore           Check WordPress core checksums before scanning.
     * @param bool           $checkUploads        Scan wp-content/uploads/ for anomalous non-media files.
     * @param string|null    $rulesDir            Directory to load custom YAML rules from.
     * @param array          $excludeDirs         Directory names to exclude from scanning.
     * @param array          $excludeExtensions   File extensions to exclude from scanning.
     * @param ScanTargetType $targetType          Resolved target classification for routing.
     */
    public function __construct(
        public string         $target,
        public OutputFormat   $outputFormat      = OutputFormat::TEXT,
        public ?string        $outputFile        = null,
        public Severity       $minSeverity       = Severity::INFORMATIONAL,
        public bool           $noColor           = false,
        public int            $workers           = 4,
        public int            $maxFileSizeBytes  = 10_485_760,
        public bool           $showProgress      = false,
        public bool           $quickMode         = false,
        public bool           $fullMode          = false,
        public bool           $checkCore         = true,
        public bool           $checkUploads      = true,
        public ?string        $rulesDir          = null,
        public array          $excludeDirs       = ['.git', 'node_modules', '.svn'],
        public array          $excludeExtensions = [
            '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg',
            '.woff', '.woff2', '.ttf', '.eot',
            '.mp4', '.mp3',
            '.zip', '.tar', '.gz',
        ],
        public ScanTargetType $targetType        = ScanTargetType::UNKNOWN,
    ) {}

    /**
     * Create a ScanConfig from CLI option values produced by Symfony Console.
     *
     * @param string $target  The scan target path (first positional argument).
     * @param array  $options Associative array of option name → value from the CLI.
     */
    public static function fromCliOptions(string $target, array $options): self
    {
        $outputFormat = isset($options['output'])
            ? (OutputFormat::tryFrom($options['output']) ?? OutputFormat::TEXT)
            : OutputFormat::TEXT;

        $minSeverity = isset($options['severity'])
            ? (Severity::tryFrom($options['severity']) ?? Severity::INFORMATIONAL)
            : Severity::INFORMATIONAL;

        $targetType = isset($options['target-type'])
            ? (ScanTargetType::tryFrom((string) $options['target-type']) ?? ScanTargetType::UNKNOWN)
            : ScanTargetType::UNKNOWN;

        return new self(
            target:             $target,
            outputFormat:       $outputFormat,
            outputFile:         $options['output-file'] ?? null,
            minSeverity:        $minSeverity,
            noColor:            (bool) ($options['no-color'] ?? false),
            workers:            (int) ($options['workers'] ?? 4),
            maxFileSizeBytes:   (int) ($options['max-file-size'] ?? 10_485_760),
            showProgress:       (bool) ($options['progress'] ?? false),
            quickMode:          (bool) ($options['quick'] ?? false),
            fullMode:           (bool) ($options['full'] ?? false),
            checkCore:          (bool) ($options['check-core'] ?? true),
            checkUploads:       (bool) ($options['check-uploads'] ?? true),
            rulesDir:           $options['rules-dir'] ?? null,
            targetType:         $targetType,
        );
    }
}
