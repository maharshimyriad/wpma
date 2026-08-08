<?php

declare(strict_types=1);

namespace Wpma\Reporting;

use Wpma\Models\FileResult;
use Wpma\Models\Finding;
use Wpma\Models\ScanReport;
use Wpma\Models\Severity;

final class CsvTaskReporter
{
    private const HEADER = [
        'Status',
        'Priority',
        'Category',
        'Task',
        'Location',
        'Details',
        'Recommended Action',
        'Rule',
    ];

    public function write(ScanReport $report, string $path): int
    {
        $handle = @fopen($path, 'wb');
        if ($handle === false) {
            throw new \RuntimeException(sprintf('Could not write CSV output file: %s', $path));
        }

        try {
            fputcsv($handle, ['WPMA SECURITY SCAN - REMEDIATION CHECKLIST']);
            fputcsv($handle, []);
            fputcsv($handle, ['Need a helping hand?']);
            fputcsv($handle, ['If you need assistance reviewing or resolving these findings, you can share this report with Myriad Solutionz at https://myriadsolutionz.com/']);
            fputcsv($handle, ['Please review each task and update the Status column as you work through the checklist.']);
            fputcsv($handle, []);
            fputcsv($handle, self::HEADER);

            $rows = $this->buildRows($report);
            foreach ($rows as $row) {
                fputcsv($handle, $row);
            }
        } finally {
            fclose($handle);
        }

        return count($rows);
    }

    /**
     * @return list<array{Status: string, Priority: string, Category: string, Task: string, Location: string, Details: string, Recommended Action: string, Rule: string}>
     */
    public function buildRows(ScanReport $report): array
    {
        $rows = [];
        $seen = [];

        foreach ($report->fileResults as $fileResult) {
            foreach ($fileResult->findings as $finding) {
                $row = $this->rowForFinding($fileResult, $finding);
                $key = implode("\x1F", $row);
                if (isset($seen[$key])) {
                    continue;
                }
                $seen[$key] = true;
                $rows[] = $row;
            }
        }

        foreach ($report->pluginIntegrity as $slug => $info) {
            if (($info['status'] ?? null) !== 'unavailable' || !(bool) ($info['malwareAnalysisSkipped'] ?? false)) {
                continue;
            }

            $location = $this->pluginLocationFromTarget($report->target, $slug);
            $row = [
                'Open',
                'Info',
                'Plugin',
                'Review unverified premium/custom plugin',
                $location,
                'Plugin is not available through the official WordPress.org verification source',
                'Verify the plugin using the original vendor package or source',
                '',
            ];

            $key = implode("\x1F", $row);
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
            $rows[] = $row;
        }

        return $rows;
    }

    /**
     * @return array{Status: string, Priority: string, Category: string, Task: string, Location: string, Details: string, Recommended Action: string, Rule: string}
     */
    private function rowForFinding(FileResult $fileResult, Finding $finding): array
    {
        return [
            'Open',
            $this->priorityFromSeverity($finding->severity),
            $this->categoryForFinding($finding),
            $this->taskForFinding($finding),
            $fileResult->relativePath !== '' ? $fileResult->relativePath : $finding->filePath,
            $finding->description !== '' ? $finding->description : $finding->explanation,
            $finding->remediation,
            $finding->ruleId,
        ];
    }

    private function priorityFromSeverity(Severity $severity): string
    {
        return match ($severity) {
            Severity::CRITICAL => 'Critical',
            Severity::HIGH => 'High',
            Severity::MEDIUM => 'Medium',
            Severity::LOW => 'Low',
            Severity::INFORMATIONAL => 'Info',
        };
    }

    private function categoryForFinding(Finding $finding): string
    {
        return match (true) {
            str_starts_with($finding->ruleId, 'INTG-') => 'Integrity',
            str_starts_with($finding->ruleId, 'UPLD-') => 'Uploads',
            default => 'Malware',
        };
    }

    private function taskForFinding(Finding $finding): string
    {
        return match ($finding->ruleId) {
            'INTG-001' => 'Remove unexpected plugin file',
            'INTG-002' => 'Restore modified plugin file',
            'INTG-003' => 'Restore missing official file',
            'UPLD-001' => 'Review executable file in uploads',
            default => 'Investigate suspicious PHP file',
        };
    }

    private function pluginLocationFromTarget(string $target, string $slug): string
    {
        $normalized = str_replace('\\', '/', $target);
        $normalized = rtrim($normalized, '/');

        if (str_ends_with($normalized, '/wp-content/plugins')) {
            return 'wp-content/plugins/' . $slug;
        }

        if (str_contains($normalized, '/wp-content/plugins/')) {
            if (preg_match('#(wp-content/plugins/[^/]+)$#', $normalized, $m)) {
                return $m[1];
            }
        }

        if (is_dir($normalized . '/wp-content/plugins/' . $slug) || !str_contains($normalized, '/wp-content/plugins')) {
            return 'wp-content/plugins/' . $slug;
        }

        return $slug;
    }
}
