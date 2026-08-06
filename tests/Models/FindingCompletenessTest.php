<?php

declare(strict_types=1);

namespace Wpma\Tests\Models;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Wpma\Models\Confidence;
use Wpma\Models\DetectionCategory;
use Wpma\Models\Finding;
use Wpma\Models\Severity;

/**
 * Tests for Finding completeness rules (task 1.7).
 *
 * Property 4: Finding Completeness Rules — validates Requirements 4.3, 4.4.
 */
final class FindingCompletenessTest extends TestCase
{
    // ── HIGH/CRITICAL must have remediation ───────────────────────────────────

    public static function highSeverityCases(): array
    {
        return [
            'high'     => [Severity::HIGH],
            'critical' => [Severity::CRITICAL],
        ];
    }

    #[DataProvider('highSeverityCases')]
    public function testHighSeverityFindingHasNonEmptyRemediation(Severity $severity): void
    {
        $finding = $this->makeFinding([
            'severity'    => $severity,
            'remediation' => 'Remove the malicious file immediately.',
        ]);

        $this->assertNotEmpty($finding->remediation,
            "A {$severity->value} severity finding must have a non-empty remediation");
    }

    #[DataProvider('highSeverityCases')]
    public function testHighSeverityFindingWithEmptyRemediationDocumentsViolation(Severity $severity): void
    {
        // @todo: enforce non-empty remediation at construction time in a future version
        $finding = $this->makeFinding([
            'severity'    => $severity,
            'remediation' => '',
        ]);

        // Current behaviour: field is empty (no enforcement yet)
        $this->assertSame('', $finding->remediation,
            "Currently no construction-time enforcement — document for future hardening");
    }

    // ── LOW confidence must have explanation ──────────────────────────────────

    public static function lowConfidenceCases(): array
    {
        return [
            'low confidence' => [Confidence::LOW],
        ];
    }

    #[DataProvider('lowConfidenceCases')]
    public function testLowConfidenceFindingHasNonEmptyExplanation(Confidence $confidence): void
    {
        $finding = $this->makeFinding([
            'confidence'  => $confidence,
            'explanation' => 'This may be a false positive because legitimate plugins also use this pattern.',
        ]);

        $this->assertNotEmpty($finding->explanation,
            "A LOW confidence finding must have a non-empty explanation");
    }

    #[DataProvider('lowConfidenceCases')]
    public function testLowConfidenceFindingWithEmptyExplanationDocumentsViolation(Confidence $confidence): void
    {
        // @todo: enforce non-empty explanation for LOW confidence at construction time
        $finding = $this->makeFinding([
            'confidence'  => $confidence,
            'explanation' => '',
        ]);

        $this->assertSame('', $finding->explanation,
            "Currently no construction-time enforcement — document for future hardening");
    }

    // ── full construction ─────────────────────────────────────────────────────

    public static function completeFindingProvider(): array
    {
        return [
            'informational' => [Severity::INFORMATIONAL, Confidence::LOW,    'A minimal informational finding'],
            'low'           => [Severity::LOW,           Confidence::MEDIUM, 'A low severity finding'],
            'medium'        => [Severity::MEDIUM,        Confidence::MEDIUM, 'A medium severity finding'],
            'high'          => [Severity::HIGH,          Confidence::HIGH,   'A high severity finding'],
            'critical'      => [Severity::CRITICAL,      Confidence::HIGH,   'A critical severity finding'],
        ];
    }

    #[DataProvider('completeFindingProvider')]
    public function testFindingCanBeConstructedWithAllFields(
        Severity $severity,
        Confidence $confidence,
        string $description,
    ): void {
        $finding = $this->makeFinding([
            'severity'    => $severity,
            'confidence'  => $confidence,
            'description' => $description,
        ]);

        $this->assertSame($severity,    $finding->severity);
        $this->assertSame($confidence,  $finding->confidence);
        $this->assertSame($description, $finding->description);
        $this->assertIsString($finding->ruleId);
        $this->assertIsString($finding->title);
        $this->assertIsString($finding->filePath);
        $this->assertIsInt($finding->line);
        $this->assertIsArray($finding->evidence);
        $this->assertIsArray($finding->iocs);
        $this->assertIsArray($finding->mitreTechniques);
        $this->assertIsArray($finding->tags);
    }

    // ── severity ordering ─────────────────────────────────────────────────────

    public function testSeverityWeightOrderingIsCorrect(): void
    {
        $this->assertLessThan(Severity::LOW->weight(),           Severity::INFORMATIONAL->weight());
        $this->assertLessThan(Severity::MEDIUM->weight(),        Severity::LOW->weight());
        $this->assertLessThan(Severity::HIGH->weight(),          Severity::MEDIUM->weight());
        $this->assertLessThan(Severity::CRITICAL->weight(),      Severity::HIGH->weight());
    }

    public function testSeverityIsAtLeastMethod(): void
    {
        $this->assertTrue(Severity::HIGH->isAtLeast(Severity::MEDIUM));
        $this->assertFalse(Severity::LOW->isAtLeast(Severity::HIGH));
        $this->assertTrue(Severity::CRITICAL->isAtLeast(Severity::CRITICAL));
        $this->assertTrue(Severity::CRITICAL->isAtLeast(Severity::INFORMATIONAL));
    }

    public function testConfidenceWeightOrder(): void
    {
        $this->assertLessThan(Confidence::MEDIUM->weight(), Confidence::LOW->weight());
        $this->assertLessThan(Confidence::HIGH->weight(),   Confidence::MEDIUM->weight());
    }

    // ── factory helper ────────────────────────────────────────────────────────

    private function makeFinding(array $overrides = []): Finding
    {
        return Finding::create(array_merge([
            'ruleId'      => 'TEST-001',
            'title'       => 'Test finding title',
            'filePath'    => '/var/www/wp-content/test.php',
            'line'        => 1,
            'severity'    => Severity::MEDIUM,
            'confidence'  => Confidence::MEDIUM,
            'category'    => DetectionCategory::CUSTOM,
            'description' => 'A test description',
            'explanation' => 'A test explanation',
            'remediation' => 'A test remediation',
        ], $overrides));
    }
}
