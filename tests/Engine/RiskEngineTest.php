<?php

declare(strict_types=1);

namespace Wpma\Tests\Engine;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Wpma\Engine\RiskEngine;
use Wpma\Models\Confidence;
use Wpma\Models\DetectionCategory;
use Wpma\Models\FileResult;
use Wpma\Models\Finding;
use Wpma\Models\Severity;
use Wpma\Models\WPContext;

/**
 * Tests for RiskEngine (task 3.4).
 *
 * **Validates: Requirements 3.1, 3.2, 3.3**
 */
final class RiskEngineTest extends TestCase
{
    private RiskEngine $engine;

    protected function setUp(): void
    {
        $this->engine = new RiskEngine();
    }

    // ── Finding scores ────────────────────────────────────────────────────────

    /**
     * All severity/confidence combinations must produce a score in [0.0, 100.0].
     */
    public static function allSeverityConfidenceCombinationsProvider(): array
    {
        $cases = [];
        foreach (Severity::cases() as $severity) {
            foreach (Confidence::cases() as $confidence) {
                $key          = "{$severity->value}+{$confidence->value}";
                $cases[$key] = [$severity, $confidence];
            }
        }
        return $cases;
    }

    #[DataProvider('allSeverityConfidenceCombinationsProvider')]
    public function testFindingScoreIsInValidRange(Severity $severity, Confidence $confidence): void
    {
        $finding = $this->makeFinding($severity, $confidence);
        $score   = $this->engine->computeFindingScore($finding);

        $this->assertGreaterThanOrEqual(0.0, $score, "Score must be >= 0.0 for {$severity->value}/{$confidence->value}");
        $this->assertLessThanOrEqual(100.0, $score, "Score must be <= 100.0 for {$severity->value}/{$confidence->value}");
    }

    public function testFindingScoreHigherSeverityProducesHigherScore(): void
    {
        $lowScore    = $this->engine->computeFindingScore($this->makeFinding(Severity::LOW,    Confidence::HIGH));
        $highScore   = $this->engine->computeFindingScore($this->makeFinding(Severity::HIGH,   Confidence::HIGH));
        $critScore   = $this->engine->computeFindingScore($this->makeFinding(Severity::CRITICAL, Confidence::HIGH));

        $this->assertGreaterThan($lowScore,  $highScore);
        $this->assertGreaterThan($highScore, $critScore);
    }

    public function testFindingScoreHigherConfidenceProducesHigherScore(): void
    {
        $lowConf    = $this->engine->computeFindingScore($this->makeFinding(Severity::HIGH, Confidence::LOW));
        $medConf    = $this->engine->computeFindingScore($this->makeFinding(Severity::HIGH, Confidence::MEDIUM));
        $highConf   = $this->engine->computeFindingScore($this->makeFinding(Severity::HIGH, Confidence::HIGH));

        $this->assertGreaterThan($lowConf, $medConf);
        $this->assertGreaterThan($medConf, $highConf);
    }

    public function testFindingScoreRoundedToTwoDecimalPlaces(): void
    {
        $finding = $this->makeFinding(Severity::MEDIUM, Confidence::MEDIUM);
        $score   = $this->engine->computeFindingScore($finding);

        // Cast to string and check decimal places
        $this->assertSame($score, round($score, 2));
    }

    // ── File scores ───────────────────────────────────────────────────────────

    public function testFileScoreIsZeroForEmptyFindings(): void
    {
        $this->assertSame(0.0, $this->engine->computeFileScore([]));
    }

    public function testFileScoreIsInValidRange(): void
    {
        $findings = [
            $this->makeFinding(Severity::CRITICAL, Confidence::HIGH),
            $this->makeFinding(Severity::HIGH,     Confidence::HIGH),
            $this->makeFinding(Severity::MEDIUM,   Confidence::MEDIUM),
        ];

        $score = $this->engine->computeFileScore($findings);

        $this->assertGreaterThanOrEqual(0.0, $score);
        $this->assertLessThanOrEqual(100.0, $score);
    }

    public function testFileScoreIncreasesWithMoreHighSeverityFindings(): void
    {
        $oneHighFinding = [
            $this->makeFinding(Severity::CRITICAL, Confidence::HIGH),
        ];

        $manyHighFindings = [
            $this->makeFinding(Severity::CRITICAL, Confidence::HIGH),
            $this->makeFinding(Severity::CRITICAL, Confidence::HIGH),
            $this->makeFinding(Severity::CRITICAL, Confidence::HIGH),
            $this->makeFinding(Severity::CRITICAL, Confidence::HIGH),
        ];

        $scoreOne  = $this->engine->computeFileScore($oneHighFinding);
        $scoreMany = $this->engine->computeFileScore($manyHighFindings);

        $this->assertGreaterThan($scoreOne, $scoreMany);
    }

    public function testFileScoreWithSingleFinding(): void
    {
        $findings = [$this->makeFinding(Severity::HIGH, Confidence::HIGH)];
        $score    = $this->engine->computeFileScore($findings);

        $this->assertGreaterThan(0.0, $score);
        $this->assertLessThanOrEqual(100.0, $score);
    }

    // ── Overall score ─────────────────────────────────────────────────────────

    public function testOverallScoreIsZeroForEmptyInput(): void
    {
        $this->assertSame(0.0, $this->engine->computeOverallScore([]));
    }

    public function testOverallScoreIsInValidRange(): void
    {
        $fileResults = [
            $this->makeFileResult(85.0),
            $this->makeFileResult(50.0),
            $this->makeFileResult(20.0),
            $this->makeFileResult(5.0),
        ];

        $score = $this->engine->computeOverallScore($fileResults);

        $this->assertGreaterThanOrEqual(0.0, $score);
        $this->assertLessThanOrEqual(100.0, $score);
    }

    public function testOverallScoreWeightsTopFilesMoreHeavily(): void
    {
        // High risk files should push the overall score higher
        $highRiskResults = [
            $this->makeFileResult(95.0),
            $this->makeFileResult(90.0),
            $this->makeFileResult(1.0),
        ];

        $lowRiskResults = [
            $this->makeFileResult(10.0),
            $this->makeFileResult(5.0),
            $this->makeFileResult(1.0),
        ];

        $highScore = $this->engine->computeOverallScore($highRiskResults);
        $lowScore  = $this->engine->computeOverallScore($lowRiskResults);

        $this->assertGreaterThan($lowScore, $highScore);
    }

    public function testOverallScoreWithSingleFileResult(): void
    {
        $fileResults = [$this->makeFileResult(60.0)];
        $score       = $this->engine->computeOverallScore($fileResults);

        $this->assertSame(60.0, $score);
    }

    // ── scoreAndSortFileResults ───────────────────────────────────────────────

    public function testScoreAndSortFileResultsReturnsSortedDescending(): void
    {
        $items = [
            $this->makeRawFileItem('/low.php',    'low.php',    [
                $this->makeFinding(Severity::LOW,      Confidence::LOW),
            ]),
            $this->makeRawFileItem('/critical.php', 'critical.php', [
                $this->makeFinding(Severity::CRITICAL, Confidence::HIGH),
                $this->makeFinding(Severity::CRITICAL, Confidence::HIGH),
            ]),
            $this->makeRawFileItem('/medium.php', 'medium.php', [
                $this->makeFinding(Severity::MEDIUM, Confidence::MEDIUM),
            ]),
        ];

        $results = $this->engine->scoreAndSortFileResults($items);

        $this->assertCount(3, $results);
        $this->assertSame('critical.php', $results[0]->relativePath);

        // Verify descending order
        for ($i = 0; $i < count($results) - 1; $i++) {
            $this->assertGreaterThanOrEqual(
                $results[$i + 1]->riskScore,
                $results[$i]->riskScore,
                "Results should be sorted descending by riskScore"
            );
        }
    }

    public function testScoreAndSortFileResultsEmptyInput(): void
    {
        $results = $this->engine->scoreAndSortFileResults([]);
        $this->assertSame([], $results);
    }

    public function testScoreAndSortFileResultsProducesFileResultObjects(): void
    {
        $items = [
            $this->makeRawFileItem('/foo.php', 'foo.php', [
                $this->makeFinding(Severity::HIGH, Confidence::HIGH),
            ]),
        ];

        $results = $this->engine->scoreAndSortFileResults($items);

        $this->assertCount(1, $results);
        $this->assertInstanceOf(FileResult::class, $results[0]);
        $this->assertSame('/foo.php', $results[0]->filePath);
        $this->assertGreaterThan(0.0, $results[0]->riskScore);
    }

    public function testScoreAndSortFileResultsEmptyFindingsYieldsZeroScore(): void
    {
        $items = [
            $this->makeRawFileItem('/empty.php', 'empty.php', []),
        ];

        $results = $this->engine->scoreAndSortFileResults($items);

        $this->assertSame(0.0, $results[0]->riskScore);
    }

    // ── Property 6: generated finding lists always produce score ∈ [0, 100] ──

    /**
     * Property 6: For any generated list of findings, computeFileScore must
     * return a value in [0.0, 100.0].
     *
     * **Validates: Requirements 3.1, 3.2**
     */
    public function testPropertyFileScoreAlwaysInValidRangeForVariedInputs(): void
    {
        $severities  = Severity::cases();
        $confidences = Confidence::cases();

        // Generate varied combinations of finding lists deterministically
        $testCases = $this->generateVariedFindingLists($severities, $confidences);

        foreach ($testCases as $label => $findings) {
            $score = $this->engine->computeFileScore($findings);

            $this->assertGreaterThanOrEqual(
                0.0,
                $score,
                "Score for '{$label}' must be >= 0.0, got {$score}"
            );
            $this->assertLessThanOrEqual(
                100.0,
                $score,
                "Score for '{$label}' must be <= 100.0, got {$score}"
            );
        }
    }

    /**
     * Property 6 (finding score variant): For every severity/confidence pair,
     * computeFindingScore must return a value in [0.0, 100.0].
     *
     * **Validates: Requirements 3.1**
     */
    public function testPropertyFindingScoreAlwaysInValidRange(): void
    {
        foreach (Severity::cases() as $severity) {
            foreach (Confidence::cases() as $confidence) {
                $finding = $this->makeFinding($severity, $confidence);
                $score   = $this->engine->computeFindingScore($finding);

                $this->assertGreaterThanOrEqual(0.0, $score);
                $this->assertLessThanOrEqual(100.0, $score);
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private function makeFinding(
        Severity   $severity   = Severity::MEDIUM,
        Confidence $confidence = Confidence::MEDIUM,
    ): Finding {
        return Finding::create([
            'ruleId'      => 'TST-001',
            'title'       => 'Test finding',
            'filePath'    => '/var/www/test.php',
            'line'        => 1,
            'severity'    => $severity,
            'confidence'  => $confidence,
            'category'    => DetectionCategory::OBFUSCATION,
            'description' => 'Test description',
            'explanation' => 'Test explanation',
            'remediation' => 'Remove it.',
            'evidence'    => [],
            'iocs'        => [],
            'mitreTechniques' => [],
            'tags'        => [],
        ]);
    }

    private function makeFileResult(float $riskScore): FileResult
    {
        return new FileResult(
            filePath:     '/var/www/test.php',
            relativePath: 'test.php',
            findings:     [],
            iocs:         [],
            riskScore:    $riskScore,
            wpContext:    null,
            scanTimeMs:   1.0,
        );
    }

    /**
     * @param Finding[] $findings
     * @return array{filePath: string, relativePath: string, findings: Finding[], iocs: array, wpContext: null, scanTimeMs: float}
     */
    private function makeRawFileItem(string $filePath, string $relativePath, array $findings): array
    {
        return [
            'filePath'     => $filePath,
            'relativePath' => $relativePath,
            'findings'     => $findings,
            'iocs'         => [],
            'wpContext'    => null,
            'scanTimeMs'   => 1.0,
        ];
    }

    /**
     * Generate a varied set of finding lists for property testing.
     *
     * @param  Severity[]   $severities
     * @param  Confidence[] $confidences
     * @return array<string, Finding[]>
     */
    private function generateVariedFindingLists(array $severities, array $confidences): array
    {
        $cases = [];

        // Empty list
        $cases['empty'] = [];

        // Single findings for each combination
        foreach ($severities as $sev) {
            foreach ($confidences as $conf) {
                $cases["single-{$sev->value}-{$conf->value}"] = [
                    $this->makeFinding($sev, $conf),
                ];
            }
        }

        // Mixed lists of increasing sizes
        $allCombinations = [];
        foreach ($severities as $sev) {
            foreach ($confidences as $conf) {
                $allCombinations[] = [$sev, $conf];
            }
        }

        for ($size = 2; $size <= 20; $size++) {
            $findings = [];
            for ($i = 0; $i < $size; $i++) {
                [$sev, $conf] = $allCombinations[$i % count($allCombinations)];
                $findings[] = $this->makeFinding($sev, $conf);
            }
            $cases["mixed-size-{$size}"] = $findings;
        }

        // Worst-case: all CRITICAL + HIGH confidence
        $cases['all-critical-high'] = array_fill(0, 10, $this->makeFinding(Severity::CRITICAL, Confidence::HIGH));

        // All lowest severity
        $cases['all-informational-low'] = array_fill(0, 5, $this->makeFinding(Severity::INFORMATIONAL, Confidence::LOW));

        return $cases;
    }
}
