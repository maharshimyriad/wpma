<?php

declare(strict_types=1);

namespace Wpma\Tests\Reporting;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Wpma\Models\Confidence;
use Wpma\Models\DetectionCategory;
use Wpma\Models\FileResult;
use Wpma\Models\Finding;
use Wpma\Models\IOC;
use Wpma\Models\IOCType;
use Wpma\Models\ScanReport;
use Wpma\Models\ScanWarning;
use Wpma\Models\Severity;
use Wpma\Reporting\JsonReporter;
use Wpma\Reporting\TextReporter;

/**
 * Tests for TextReporter IOC presentation behaviour.
 *
 * Rules under test:
 *   - Raw IOC values must NOT appear in text output
 *   - Zero IOCs  => no NOTES section unless other notes exist
 *   - One IOC    => NOTES appears once
 *   - Many IOCs  => exactly one suspicious-indicator note
 *   - Premium/custom + IOC notes are combined into one final NOTES section
 *   - NOTES is the last substantive section
 *   - Severity counts and overall risk are unaffected by IOC presence
 *   - JSON output retains complete IOC data
 */
final class TextReporterTest extends TestCase
{
    // ── No IOCs => no NOTES unless other note content exists ──────────────────

    public function testNeitherPremiumCustomNorIocsProducesNoNotesSection(): void
    {
        $report = $this->makeReport(iocs: []);
        $text   = $this->render($report);

        $this->assertStringNotContainsString('NOTES', $text);
        $this->assertStringNotContainsString('suspicious indicators', $text);
    }

    // ── One IOC => NOTES appears ──────────────────────────────────────────────

    public function testSuspiciousIndicatorNoteOnlyUsesSingleNotesSection(): void
    {
        $report = $this->makeReport(iocs: [$this->makeIoc('evil.ru')]);
        $text   = $this->render($report);

        $this->assertStringContainsString('NOTES', $text);
        $this->assertStringContainsString('suspicious indicators', $text);
        $this->assertSame(1, substr_count($text, 'NOTES'));
    }

    // ── Many IOCs => exactly one NOTE ────────────────────────────────────────

    public function testManyIocsProduceExactlyOneNote(): void
    {
        $iocs = [];
        for ($i = 1; $i <= 25; $i++) {
            $iocs[] = $this->makeIoc("evil-{$i}.example.com");
        }

        $report = $this->makeReport(iocs: $iocs);
        $text   = $this->render($report);

        $this->assertSame(
            1,
            substr_count($text, 'Additional suspicious indicators were found'),
            'Exactly one suspicious-indicator note must appear regardless of IOC count',
        );
        $this->assertSame(1, substr_count($text, 'NOTES'));
    }

    // ── Raw IOC values do not appear in text output ───────────────────────────

    public function testRawIocValueIsNotDumpedInTextOutput(): void
    {
        $sentinel = 'totally-unique-evil-payload-' . bin2hex(random_bytes(4)) . '.ru';
        $report   = $this->makeReport(iocs: [$this->makeIoc($sentinel)]);
        $text     = $this->render($report);

        $this->assertStringNotContainsString($sentinel, $text,
            'Raw IOC value must not appear anywhere in text output');
    }

    public function testBase64BlobIocValueDoesNotAppearInTextOutput(): void
    {
        $blob   = base64_encode('<?php eval($_POST["x"]); ?>');
        $ioc    = new IOC(IOCType::BASE64_BLOB, $blob, '/var/www/test.php', 5);
        $report = $this->makeReport(iocs: [$ioc]);
        $text   = $this->render($report);

        $this->assertStringNotContainsString($blob, $text,
            'Base64 blob IOC value must not appear in text output');
    }

    public function testNoSuspiciousIocsSectionHeaderInTextOutput(): void
    {
        $report = $this->makeReport(iocs: [$this->makeIoc('bad-actor.net')]);
        $text   = $this->render($report);

        $this->assertStringNotContainsString('SUSPICIOUS IOCs', $text,
            'Old SUSPICIOUS IOCs section header must not appear');
    }

    public function testPremiumCustomNoteOnlyUsesSingleNotesSection(): void
    {
        $report = $this->makeReport(
            pluginIntegrity: [
                'premium-plugin' => [
                    'status' => 'unavailable',
                    'version' => '2.1.0',
                    'method' => 'unavailable',
                    'officialCount' => 0,
                    'localCount' => 2,
                    'okCount' => 0,
                    'modifiedFiles' => [],
                    'unexpectedFiles' => [],
                    'missingFiles' => [],
                    'officialSourceAvailable' => false,
                    'malwareAnalysisSkipped' => true,
                ],
            ],
        );

        $text = $this->render($report);

        $this->assertStringContainsString('Unverified [premium/custom]', $text);
        $this->assertStringContainsString('Official WordPress.org release: Not available', $text);
        $this->assertStringContainsString('Malware analysis: Skipped', $text);
        $this->assertStringContainsString('NOTES', $text);
        $this->assertStringContainsString('behavioral malware analysis', $text);
        $this->assertStringNotContainsString('Additional suspicious indicators were found during analysis.', $text);
        $this->assertSame(1, substr_count($text, 'NOTES'));
    }

    public function testBothPremiumCustomAndSuspiciousIndicatorMessagesAreCombinedUnderOneNotesSection(): void
    {
        $report = $this->makeReport(
            iocs: [$this->makeIoc('evil.ru')],
            pluginIntegrity: [
                'premium-plugin' => [
                    'status' => 'unavailable',
                    'version' => '2.1.0',
                    'method' => 'unavailable',
                    'officialCount' => 0,
                    'localCount' => 2,
                    'okCount' => 0,
                    'modifiedFiles' => [],
                    'unexpectedFiles' => [],
                    'missingFiles' => [],
                    'officialSourceAvailable' => false,
                    'malwareAnalysisSkipped' => true,
                ],
            ],
        );

        $text = $this->render($report);

        $this->assertSame(1, substr_count($text, 'NOTES'));
        $this->assertStringContainsString('behavioral malware analysis', $text);
        $this->assertStringContainsString('Additional suspicious indicators were found during analysis.', $text);
        $this->assertStringNotContainsString("\nNOTE\n", $text);
    }

    public function testMultipleSkippedPremiumCustomPluginsProduceCountedSummaryNote(): void
    {
        $report = $this->makeReport(
            pluginIntegrity: [
                'premium-one' => [
                    'status' => 'unavailable',
                    'version' => '',
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
                'premium-two' => [
                    'status' => 'unavailable',
                    'version' => '',
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
            ],
        );

        $text = $this->render($report);

        $this->assertStringContainsString('2 premium/custom plugins were not available through the official', $text);
    }

    // ── NOTES appears after Warnings / Findings and is final ──────────────────

    public function testNotesAppearsAfterWarningsSection(): void
    {
        $report = $this->makeReport(
            findings: [$this->makeFinding()],
            iocs:     [$this->makeIoc('evil.ru')],
            warnings: [new ScanWarning('parse failed', '/tmp/x.php', 'parse_error')],
        );
        $text = $this->render($report);

        $posWarnings = strpos($text, 'WARNINGS');
        $posNotes    = strpos($text, 'NOTES');

        $this->assertNotFalse($posWarnings, 'WARNINGS section must be present');
        $this->assertNotFalse($posNotes,    'NOTES must be present');
        $this->assertGreaterThan($posWarnings, $posNotes,
            'NOTES must appear after WARNINGS');
    }

    public function testNotesAppearsAfterFindingsSection(): void
    {
        $report = $this->makeReport(
            findings: [$this->makeFinding()],
            iocs:     [$this->makeIoc('evil.ru')],
        );
        $text = $this->render($report);

        $posFindings = strpos($text, 'FINDINGS');
        $posNotes    = strpos($text, 'NOTES');

        $this->assertNotFalse($posNotes,    'NOTES must be present');
        $this->assertNotFalse($posFindings, 'FINDINGS section must be present');
        $this->assertGreaterThan($posFindings, $posNotes,
            'NOTES must come after FINDINGS section');
    }

    public function testNotesRemainsTheFinalSectionOfTheTextReport(): void
    {
        $report = $this->makeReport(
            findings: [$this->makeFinding()],
            iocs: [$this->makeIoc('evil.ru')],
            warnings: [new ScanWarning('parse failed', '/tmp/x.php', 'parse_error')],
            pluginIntegrity: [
                'premium-plugin' => [
                    'status' => 'unavailable',
                    'version' => '2.1.0',
                    'method' => 'unavailable',
                    'officialCount' => 0,
                    'localCount' => 2,
                    'okCount' => 0,
                    'modifiedFiles' => [],
                    'unexpectedFiles' => [],
                    'missingFiles' => [],
                    'officialSourceAvailable' => false,
                    'malwareAnalysisSkipped' => true,
                ],
            ],
        );

        $text = rtrim($this->render($report));
        $posNotes = strrpos($text, 'NOTES');
        $this->assertNotFalse($posNotes, 'NOTES must be present');
        $tail = substr($text, $posNotes);
        $this->assertStringNotContainsString('WARNINGS', $tail);
        $this->assertStringNotContainsString('PLUGIN INTEGRITY', $tail);
        $this->assertStringContainsString('Additional suspicious indicators were found during analysis.', $tail);
    }

    // ── Severity counts are unaffected by IOC presence ───────────────────────

    public function testSeverityCountsAreUnchangedByIocPresence(): void
    {
        $finding = $this->makeFinding();

        $textNo   = $this->render($this->makeReport(findings: [$finding], iocs: []));
        $textWith = $this->render($this->makeReport(findings: [$finding], iocs: [$this->makeIoc('x.ru')]));

        preg_match('/Medium\s*:\s*(\d+)/', $textNo,   $mNo);
        preg_match('/Medium\s*:\s*(\d+)/', $textWith, $mWith);

        $this->assertSame(
            $mNo[1] ?? '-1',
            $mWith[1] ?? '-2',
            'Medium finding count must be identical with and without IOCs',
        );
    }

    public function testOverallRiskIsUnchangedByIocPresence(): void
    {
        $finding = $this->makeFinding();

        $textNo   = $this->render($this->makeReport(findings: [$finding], iocs: [],                       riskScore: 16.0));
        $textWith = $this->render($this->makeReport(findings: [$finding], iocs: [$this->makeIoc('x.ru')], riskScore: 16.0));

        preg_match('/Overall Risk\s*:\s*(\S+)/', $textNo,   $rNo);
        preg_match('/Overall Risk\s*:\s*(\S+)/', $textWith, $rWith);

        $this->assertSame(
            $rNo[1] ?? '-1',
            $rWith[1] ?? '-2',
            'Overall Risk label must be identical with and without IOCs',
        );
    }

    // ── JSON output retains complete IOC data ─────────────────────────────────

    public function testJsonOutputRetainsAllIocData(): void
    {
        $sentinel = 'unique-ioc-value-' . bin2hex(random_bytes(4));
        $ioc      = new IOC(
            type:                IOCType::DOMAIN,
            value:               $sentinel,
            filePath:            '/var/www/evil.php',
            line:                7,
            isPrivateIp:         false,
            isKnownWpService:    false,
            isConfirmedMalicious: true,
            tiCategory:          'c2',
            tiReference:         'ref-123',
        );

        $report = $this->makeReport(iocs: [$ioc]);
        $json   = (new JsonReporter())->render($report);
        $data   = json_decode($json, true);

        $this->assertNotEmpty($data['allIocs'],
            'JSON must still include allIocs array');
        $this->assertSame($sentinel, $data['allIocs'][0]['value'],
            'IOC value must be present in JSON');
        $this->assertSame('domain', $data['allIocs'][0]['type']);
        $this->assertSame(7, $data['allIocs'][0]['line']);
        $this->assertTrue($data['allIocs'][0]['isConfirmedMalicious']);
        $this->assertSame('c2', $data['allIocs'][0]['tiCategory']);
    }

    // ── NOTE wording uses "indicators", not "files" ───────────────────────────

    public function testNoteUsesWordIndicatorsNotFiles(): void
    {
        $report = $this->makeReport(
            findings: [$this->makeFinding()],
            iocs:     [$this->makeIoc('evil.ru')],
        );
        $text = $this->render($report);

        $noteStart = strpos($text, 'NOTES');
        $this->assertNotFalse($noteStart, 'NOTES section must be present');
        $noteText = substr($text, $noteStart);

        $this->assertStringNotContainsString('suspicious files', $noteText,
            'NOTE must not say "suspicious files"');
        $this->assertStringContainsString('indicators', $noteText,
            'NOTE must use the word "indicators"');
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private function render(ScanReport $report): string
    {
        return (new TextReporter(noColor: true))->render($report);
    }

    private function makeIoc(string $value): IOC
    {
        return new IOC(
            type:     IOCType::DOMAIN,
            value:    $value,
            filePath: '/var/www/wp-content/evil.php',
            line:     1,
        );
    }

    private function makeFinding(): Finding
    {
        return Finding::create([
            'ruleId'      => 'BACK-001',
            'title'       => 'Dangerous function call',
            'filePath'    => '/var/www/test.php',
            'line'        => 10,
            'severity'    => Severity::MEDIUM,
            'confidence'  => Confidence::HIGH,
            'category'    => DetectionCategory::BACKDOOR,
            'description' => 'eval() called with user input',
            'explanation' => 'This is suspicious.',
            'remediation' => 'Remove it.',
        ]);
    }

    /**
     * @param Finding[]     $findings
     * @param IOC[]         $iocs
     * @param ScanWarning[] $warnings
     */
    private function makeReport(
        array $findings  = [],
        array $iocs      = [],
        array $warnings  = [],
        float $riskScore = 0.0,
        array $pluginIntegrity = [],
    ): ScanReport {
        $fileResults = [];
        if ($findings !== []) {
            $fileResults[] = new FileResult(
                filePath:     '/var/www/test.php',
                relativePath: 'test.php',
                findings:     $findings,
                iocs:         [],
                riskScore:    $riskScore > 0.0 ? $riskScore : 16.0,
                wpContext:    null,
                scanTimeMs:   1.0,
            );
        }

        $effectiveRisk = $riskScore > 0.0
            ? $riskScore
            : ($findings !== [] ? 16.0 : 0.0);

        return new ScanReport(
            scanId:           'test-scan-001',
            target:           '/var/www',
            startedAt:        new DateTimeImmutable('2026-01-01T00:00:00+00:00'),
            completedAt:      new DateTimeImmutable('2026-01-01T00:00:01+00:00'),
            durationMs:       1000.0,
            filesScanned:     1,
            filesSkipped:     0,
            fileResults:      $fileResults,
            allIocs:          $iocs,
            correlations:     [],
            warnings:         $warnings,
            overallRiskScore: $effectiveRisk,
            pluginIntegrity:  $pluginIntegrity,
        );
    }
}
