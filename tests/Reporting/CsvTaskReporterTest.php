<?php

declare(strict_types=1);

namespace Wpma\Tests\Reporting;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Wpma\Models\Confidence;
use Wpma\Models\DetectionCategory;
use Wpma\Models\FileResult;
use Wpma\Models\Finding;
use Wpma\Models\ScanReport;
use Wpma\Models\Severity;
use Wpma\Reporting\CsvTaskReporter;
use Wpma\Reporting\JsonReporter;
use Wpma\Reporting\TextReporter;

final class CsvTaskReporterTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tmpDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'wpma-csv-' . bin2hex(random_bytes(6));
        mkdir($this->tmpDir, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeDirectory($this->tmpDir);
        parent::tearDown();
    }

    public function testWriteCreatesCsvFileWithHeadingSupportSectionAndHeader(): void
    {
        $reporter = new CsvTaskReporter();
        $path = $this->tmpDir . DIRECTORY_SEPARATOR . 'report.csv';

        $count = $reporter->write($this->makeReport(), $path);

        $this->assertSame(0, $count);
        $this->assertFileExists($path);
        $rows = $this->readCsv($path);
        $this->assertSame(['WPMA SECURITY SCAN - REMEDIATION CHECKLIST'], $rows[0]);
        $this->assertSame([null], $rows[1]);
        $this->assertSame(['Need a helping hand?'], $rows[2]);
        $this->assertSame(['If you need assistance reviewing or resolving these findings, you can share this report with Myriad Solutionz at https://myriadsolutionz.com/'], $rows[3]);
        $this->assertSame(['Please review each task and update the Status column as you work through the checklist.'], $rows[4]);
        $this->assertSame([null], $rows[5]);
        $this->assertSame([
            'Status', 'Priority', 'Category', 'Task', 'Location', 'Details', 'Recommended Action', 'Rule',
        ], $rows[6]);
        $this->assertCount(7, $rows);
    }

    public function testExistingFindingBecomesActionableTask(): void
    {
        $finding = $this->makeFinding('BACK-001', Severity::CRITICAL, 'Potential malicious behavior detected', 'Inspect the file and remove it if confirmed malicious');
        $rows = (new CsvTaskReporter())->buildRows($this->makeReport(findings: [$finding]));

        $this->assertCount(1, $rows);
        $this->assertSame('Open', $rows[0][0]);
        $this->assertSame('Critical', $rows[0][1]);
        $this->assertSame('Malware', $rows[0][2]);
        $this->assertSame('Investigate suspicious PHP file', $rows[0][3]);
        $this->assertSame('BACK-001', $rows[0][7]);
    }

    public function testCleanVerifiedFilesDoNotBecomeTasks(): void
    {
        $rows = (new CsvTaskReporter())->buildRows($this->makeReport());
        $this->assertSame([], $rows);
    }

    public function testModifiedIntegrityFindingBecomesTask(): void
    {
        $finding = $this->makeFinding('INTG-002', Severity::HIGH, 'File differs from the official WordPress.org release', 'Compare with a clean release and restore it if the modification is unexpected');
        $rows = (new CsvTaskReporter())->buildRows($this->makeReport(findings: [$finding]));

        $this->assertSame('Integrity', $rows[0][2]);
        $this->assertSame('Restore modified plugin file', $rows[0][3]);
        $this->assertSame('INTG-002', $rows[0][7]);
    }

    public function testUnexpectedFileFindingBecomesTask(): void
    {
        $finding = $this->makeFinding('INTG-001', Severity::HIGH, 'Unexpected file in verified plugin', 'Inspect the file contents immediately');
        $rows = (new CsvTaskReporter())->buildRows($this->makeReport(findings: [$finding]));

        $this->assertSame('Remove unexpected plugin file', $rows[0][3]);
    }

    public function testMissingFileFindingBecomesTask(): void
    {
        $finding = $this->makeFinding('INTG-003', Severity::INFORMATIONAL, 'Missing official file', 'Reinstall the plugin from WordPress.org');
        $rows = (new CsvTaskReporter())->buildRows($this->makeReport(findings: [$finding]));

        $this->assertSame('Info', $rows[0][1]);
        $this->assertSame('Restore missing official file', $rows[0][3]);
    }

    public function testUpld001CreatesUploadsReviewTask(): void
    {
        $finding = $this->makeFinding('UPLD-001', Severity::MEDIUM, 'PHP file found in uploads; WPMA did not detect suspicious behavior in the file', 'Confirm whether the file was intentionally created by a legitimate plugin');
        $rows = (new CsvTaskReporter())->buildRows($this->makeReport(findings: [$finding]));

        $this->assertSame('Uploads', $rows[0][2]);
        $this->assertSame('Review executable file in uploads', $rows[0][3]);
    }

    public function testUnverifiedPremiumCustomPluginCreatesReviewTask(): void
    {
        $rows = (new CsvTaskReporter())->buildRows($this->makeReport(pluginIntegrity: [
            'example' => [
                'status' => 'unavailable',
                'version' => '1.0.0',
                'method' => 'unavailable',
                'officialCount' => 0,
                'localCount' => 1,
                'okCount' => 0,
                'modifiedFiles' => [],
                'unexpectedFiles' => [],
                'missingFiles' => [],
                'officialSourceAvailable' => false,
                'malwareAnalysisSkipped' => true,
            ],
        ]));

        $this->assertCount(1, $rows);
        $this->assertSame('Info', $rows[0][1]);
        $this->assertSame('Plugin', $rows[0][2]);
        $this->assertSame('Review unverified premium/custom plugin', $rows[0][3]);
        $this->assertSame('wp-content/plugins/example', $rows[0][4]);
        $this->assertSame('', $rows[0][7]);
    }

    public function testDuplicateFindingsDoNotCreateDuplicateTasks(): void
    {
        $finding = $this->makeFinding('BACK-001', Severity::HIGH, 'Potential malicious behavior detected', 'Inspect the file');
        $rows = (new CsvTaskReporter())->buildRows($this->makeReport(findings: [$finding, $finding]));
        $this->assertCount(1, $rows);
    }

    public function testCsvCorrectlyEscapesCommasQuotesAndMultilineDetails(): void
    {
        $finding = $this->makeFinding(
            'BACK-001',
            Severity::HIGH,
            "Value with comma, quote \" and\nmultiple lines",
            "Fix, then \"review\"\ncarefully"
        );

        $reporter = new CsvTaskReporter();
        $path = $this->tmpDir . DIRECTORY_SEPARATOR . 'escaped.csv';
        $reporter->write($this->makeReport(findings: [$finding]), $path);

        $rows = $this->readCsv($path);
        $this->assertSame("Value with comma, quote \" and\nmultiple lines", $rows[7][5]);
        $this->assertSame("Fix, then \"review\"\ncarefully", $rows[7][6]);
    }

    public function testRunningWithoutCsvDoesNotCreateFileImplicitly(): void
    {
        $this->assertSame([], glob($this->tmpDir . DIRECTORY_SEPARATOR . '*.csv') ?: []);
    }

    public function testZeroFindingsStillProducesHeadingSupportSectionAndHeaderOnlyCsv(): void
    {
        $reporter = new CsvTaskReporter();
        $path = $this->tmpDir . DIRECTORY_SEPARATOR . 'empty.csv';
        $count = $reporter->write($this->makeReport(), $path);

        $this->assertSame(0, $count);
        $rows = $this->readCsv($path);
        $this->assertSame(['WPMA SECURITY SCAN - REMEDIATION CHECKLIST'], $rows[0]);
        $this->assertSame(['Need a helping hand?'], $rows[2]);
        $this->assertSame(['If you need assistance reviewing or resolving these findings, you can share this report with Myriad Solutionz at https://myriadsolutionz.com/'], $rows[3]);
        $this->assertSame(['Please review each task and update the Status column as you work through the checklist.'], $rows[4]);
        $this->assertSame([
            'Status', 'Priority', 'Category', 'Task', 'Location', 'Details', 'Recommended Action', 'Rule',
        ], $rows[6]);
        $this->assertCount(7, $rows);
    }

    public function testJsonOutputRemainsUnchanged(): void
    {
        $report = $this->makeReport(findings: [$this->makeFinding('BACK-001', Severity::HIGH, 'x', 'y')]);
        $json = (new JsonReporter())->render($report);
        $data = json_decode($json, true);

        $this->assertSame('BACK-001', $data['fileResults'][0]['findings'][0]['ruleId']);
        $this->assertArrayNotHasKey('csv', $data);
    }

    public function testTextOutputRemainsUnchangedWithoutCsvMessageInjection(): void
    {
        $report = $this->makeReport(findings: [$this->makeFinding('BACK-001', Severity::HIGH, 'x', 'y')]);
        $text = (new TextReporter(noColor: true))->render($report);

        $this->assertStringNotContainsString('CSV REPORT', $text);
        $this->assertStringContainsString('FINDINGS', $text);
    }

    private function makeFinding(string $ruleId, Severity $severity, string $description, string $remediation): Finding
    {
        return Finding::create([
            'ruleId' => $ruleId,
            'title' => 'Title',
            'filePath' => '/var/www/wp-content/plugins/example/shell.php',
            'line' => 10,
            'severity' => $severity,
            'confidence' => Confidence::HIGH,
            'category' => str_starts_with($ruleId, 'INTG-') ? DetectionCategory::INTEGRITY : DetectionCategory::BACKDOOR,
            'description' => $description,
            'explanation' => $description,
            'remediation' => $remediation,
        ]);
    }

    /** @param Finding[] $findings */
    private function makeReport(array $findings = [], array $pluginIntegrity = []): ScanReport
    {
        $fileResults = [];
        if ($findings !== []) {
            $fileResults[] = new FileResult(
                filePath: '/var/www/wp-content/plugins/example/shell.php',
                relativePath: 'wp-content/plugins/example/shell.php',
                findings: $findings,
                iocs: [],
                riskScore: 50.0,
                wpContext: null,
                scanTimeMs: 1.0,
            );
        }

        return new ScanReport(
            scanId: 'scan-1',
            target: '/var/www/html',
            startedAt: new DateTimeImmutable('2026-01-01T00:00:00+00:00'),
            completedAt: new DateTimeImmutable('2026-01-01T00:00:01+00:00'),
            durationMs: 1000.0,
            filesScanned: $findings === [] ? 0 : 1,
            filesSkipped: 0,
            fileResults: $fileResults,
            allIocs: [],
            correlations: [],
            warnings: [],
            overallRiskScore: $findings === [] ? 0.0 : 50.0,
            pluginIntegrity: $pluginIntegrity,
        );
    }

    /** @return list<list<string>> */
    private function readCsv(string $path): array
    {
        $handle = fopen($path, 'rb');
        if ($handle === false) {
            throw new \RuntimeException('Failed to open CSV for reading');
        }

        $rows = [];
        try {
            while (($row = fgetcsv($handle)) !== false) {
                $rows[] = $row;
            }
        } finally {
            fclose($handle);
        }

        return $rows;
    }

    private function removeDirectory(string $path): void
    {
        if (!is_dir($path)) {
            return;
        }

        $items = scandir($path) ?: [];
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }

            $full = $path . DIRECTORY_SEPARATOR . $item;
            if (is_dir($full)) {
                $this->removeDirectory($full);
            } else {
                @unlink($full);
            }
        }

        @rmdir($path);
    }
}
