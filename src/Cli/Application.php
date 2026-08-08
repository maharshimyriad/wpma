<?php

declare(strict_types=1);

namespace Wpma\Cli;

use Wpma\Config\ScanConfig;
use Wpma\Detectors\BackdoorDetector;
use Wpma\Detectors\DropperDetector;
use Wpma\Detectors\HtaccessDetector;
use Wpma\Detectors\SEOSpamDetector;
use Wpma\Engine\ScanOrchestrator;
use Wpma\Engine\ScanPlan;
use Wpma\Engine\ScanProgress;
use Wpma\Models\OutputFormat;
use Wpma\Models\Severity;
use Wpma\Reporting\CsvTaskReporter;
use Wpma\Reporting\JsonReporter;
use Wpma\Reporting\TextReporter;

/**
 * Application — the WPMA CLI entry point.
 *
 * Usage:
 *   php wpma.php scan /path/to/wordpress
 *   php wpma.php scan /path --output json --output-file report.json
 *   php wpma.php version
 */
class Application
{
    private const VERSION = '2.0.0';

    public static function main(): void
    {
        global $argv;
        $args = array_slice($argv ?? [], 1);

        if (empty($args) || in_array($args[0], ['--help', '-h'], true)) {
            self::printHelp();
            exit(0);
        }

        $command = $args[0];

        match ($command) {
            'scan'    => self::runScan(array_slice($args, 1)),
            'version' => self::runVersion(),
            default   => self::unknownCommand($command),
        };
    }

    // ── commands ──────────────────────────────────────────────────────────────

    private static function runVersion(): void
    {
        echo 'WPMA v' . self::VERSION . ' — WordPress Malware Analysis Toolkit' . PHP_EOL;
        exit(0);
    }

    private static function runScan(array $args): void
    {
        if (in_array('--help', $args, true) || in_array('-h', $args, true)) {
            self::printHelp();
            exit(0);
        }

        [$target, $options] = self::parseScanArguments($args);

        $detectedTarget = ScanTargetResolver::resolve($target, $options);
        if (!$detectedTarget->isValid()) {
            fwrite(STDERR, "Error: {$detectedTarget->validationError}\n");
            exit(2);
        }

        if (!empty($options['json'])) {
            $options['output'] = 'json';
        }
        if (!empty($options['quiet'])) {
            $options['progress'] = false;
        }

        $options['target-type'] = $detectedTarget->targetType->value;

        // Build config
        $config = ScanConfig::fromCliOptions($detectedTarget->resolvedPath, $options);

        // Build detectors
        $detectors = [
            new SEOSpamDetector(),
            new BackdoorDetector(),
            new DropperDetector(),
            new HtaccessDetector(),
        ];

        $scanPlan = ScanPlan::forConfig($config);
        $progress = new ScanProgress($config, $scanPlan);

        // Build orchestrator
        $orchestrator = new ScanOrchestrator(
            $config,
            $detectors,
            fileListPath:       $options['file-list']       ?? null,
            suspiciousListPath: $options['suspicious-list'] ?? null,
            progress:           $progress,
        );

        $onProgress = $config->showProgress
            ? static function (int $done, int $total, string $file) use ($progress): void {
                $progress->updateMalwareProgress($done, $total, $file);
            }
            : null;

        // Run
        $report = $orchestrator->scan($onProgress);

        if ($config->showProgress && !$config->quickMode) {
            $progress->completeMalwareAnalysis();
        }

        // Render
        $reporter = match ($config->outputFormat) {
            OutputFormat::JSON => new JsonReporter(),
            OutputFormat::TEXT => new TextReporter($config->noColor),
            default            => new TextReporter($config->noColor),
        };

        $output = $reporter->render($report);

        // Write output
        if ($config->outputFile !== null) {
            $written = file_put_contents($config->outputFile, $output);
            if ($written === false) {
                fwrite(STDERR, "Error: could not write output file: {$config->outputFile}\n");
                exit(2);
            }
            $totalFindings = array_sum(array_map(fn($fr) => count($fr->findings), $report->fileResults));
            echo "Report written to: {$config->outputFile} ({$totalFindings} findings)\n";
        } else {
            echo $output;
        }

        if (!empty($options['csv'])) {
            $csvPath = self::generateCsvReportPath();
            try {
                $taskCount = (new CsvTaskReporter())->write($report, $csvPath);
            } catch (\Throwable $e) {
                fwrite(STDERR, "Error: could not write CSV output file: {$csvPath}\n");
                exit(2);
            }

            echo "\nCSV REPORT\n";
            echo "──────────────────────────────────────────────────\n";
            echo sprintf("  Tasks generated : %d\n", $taskCount);
            echo sprintf("  Output          : %s\n", basename($csvPath));
        }

        // Exit code: 0 = clean, 1 = findings, 2 = error
        $hasFindings = array_sum(array_map(fn($fr) => count($fr->findings), $report->fileResults)) > 0;
        exit($hasFindings ? 1 : 0);
    }

    /**
     * @param list<string> $args
     * @return array{0: string|null, 1: array<string, mixed>}
     */
    private static function parseScanArguments(array $args): array
    {
        $target = null;
        $options = [
            'output'          => 'text',
            'output-file'     => null,
            'severity'        => 'informational',
            'no-color'        => false,
            'workers'         => 4,
            'max-file-size'   => 10485760,
            'progress'        => false,
            'quiet'           => false,
            'json'            => false,
            'rules-dir'       => null,
            'file-list'       => null,
            'suspicious-list' => null,
            'quick'           => false,
            'full'            => false,
            'check-core'      => true,
            'check-uploads'   => true,
            'full-site'       => false,
            'core'            => false,
            'plugins'         => false,
            'themes'          => false,
            'file'            => false,
            'csv'             => false,
        ];

        $booleanFlags = [
            '--no-color'  => 'no-color',
            '--progress'  => 'progress',
            '--quiet'     => 'quiet',
            '--json'      => 'json',
            '--quick'     => 'quick',
            '--full'      => 'full',
            '--no-core'   => 'check-core',
            '--no-uploads'=> 'check-uploads',
            '--full-site' => 'full-site',
            '--core'      => 'core',
            '--plugins'   => 'plugins',
            '--themes'    => 'themes',
            '--file'      => 'file',
            '--csv'       => 'csv',
        ];

        $valueFlags = [
            '--output'          => 'output',
            '--output-file'     => 'output-file',
            '--severity'        => 'severity',
            '--workers'         => 'workers',
            '--max-file-size'   => 'max-file-size',
            '--rules-dir'       => 'rules-dir',
            '--file-list'       => 'file-list',
            '--suspicious-list' => 'suspicious-list',
        ];

        $i = 0;
        while ($i < count($args)) {
            $arg = $args[$i];

            if (isset($booleanFlags[$arg])) {
                $key = $booleanFlags[$arg];
                $options[$key] = str_starts_with($arg, '--no-') ? false : true;
                $i++;
                continue;
            }

            if (isset($valueFlags[$arg])) {
                if (!isset($args[$i + 1])) {
                    fwrite(STDERR, "Error: missing value for option {$arg}\n");
                    exit(2);
                }

                $options[$valueFlags[$arg]] = $args[$i + 1];
                $i += 2;
                continue;
            }

            if (str_starts_with($arg, '--')) {
                $key = ltrim(substr($arg, 2), '-');
                $key = str_replace('_', '-', $key);
                if (isset($args[$i + 1]) && !str_starts_with($args[$i + 1], '--')) {
                    $options[$key] = $args[$i + 1];
                    $i += 2;
                    continue;
                }
                $i++;
                continue;
            }

            if ($target === null && !str_starts_with($arg, '-')) {
                $target = $arg;
            }

            $i++;
        }

        return [$target, $options];
    }

    private static function unknownCommand(string $cmd): void
    {
        fwrite(STDERR, "Unknown command: {$cmd}\n");
        self::printHelp();
        exit(2);
    }

    private static function printHelp(): void
    {
        echo <<<HELP
WPMA v2 — WordPress Malware Analysis Toolkit

Usage:
  php wpma.php scan [target] [options]
  php wpma.php version

Commands:
  scan      Scan a WordPress site, plugin directory, theme, uploads path, file, or generic directory
  version   Print version and exit

Scan mode:
  (default)          Smart scan: integrity check first, deep scan only if issues found
  --quick            Integrity check only — no deep malware scan (fast)
  --full             Force deep scan all files — bypass verified-component skip

Target selection:
  [target]           Optional; defaults to the current directory when omitted
  --full-site        Force full WordPress site detection
  --core             Force WordPress core target detection
  --plugins          Force wp-content/plugins detection
  --themes           Force wp-content/themes detection
  --file             Force single-file detection

Scope flags:
  --no-core          Skip WordPress core checksum verification
  --no-uploads       Skip uploads directory anomaly scan

Output:
  --output [text|json]                 Output format (default: text)
  --json                               Shortcut for --output json
  --csv                                Generate an actionable remediation checklist CSV in addition to the terminal report
  --output-file <path>                 Write report to file
  --severity [info|low|medium|high|critical]  Minimum severity (default: informational)
  --no-color                           Disable ANSI colors
  --progress                           Show detailed progress (integrity + per-file)
  --quiet                              Suppress progress/status output

Performance:
  --max-file-size <bytes>              Max file size to scan (default: 10485760)
  --workers <n>                        Worker count (default: 4)

Examples:
  php wpma.php scan /var/www/html                 Smart scan entire WP site
  php wpma.php scan --plugins /var/www/html      Scan the site's plugins directory
  php wpma.php scan /var/www/html --quick        Integrity check only
  php wpma.php scan /var/www/html --full         Force deep scan everything
  php wpma.php scan wp-content/plugins/my-plugin Scan a single plugin

Exit codes:
  0   No findings
  1   Findings detected
  2   Fatal error

HELP;
    }

    private static function generateCsvReportPath(): string
    {
        return getcwd() . DIRECTORY_SEPARATOR . 'wpma-report-' . date('Y-m-d-Hi') . '.csv';
    }
}
