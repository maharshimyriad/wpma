<?php

declare(strict_types=1);

namespace Wpma\Engine;

use Wpma\Models\Confidence;
use Wpma\Models\FileResult;
use Wpma\Models\Finding;
use Wpma\Models\IOC;
use Wpma\Models\Severity;
use Wpma\Models\WPContext;

/**
 * RiskEngine — stateless scoring engine that converts raw findings and file
 * results into normalised risk scores in the range [0.0, 100.0].
 *
 * Scoring matrix  (base = severityWeight * confidenceWeight * 2.0):
 *   Severity weights  : INFORMATIONAL=1, LOW=2, MEDIUM=4, HIGH=8, CRITICAL=16
 *   Confidence weights: LOW=1, MEDIUM=2, HIGH=3
 *   Scale factor      : 2.0  → range ≈ 2–96
 */
final class RiskEngine
{
    // ── Severity weights ──────────────────────────────────────────────────────

    private const SEVERITY_WEIGHT = [
        'informational' => 1,
        'low'           => 2,
        'medium'        => 4,
        'high'          => 8,
        'critical'      => 16,
    ];

    // ── Confidence weights ────────────────────────────────────────────────────

    private const CONFIDENCE_WEIGHT = [
        'low'    => 1,
        'medium' => 2,
        'high'   => 3,
    ];

    // ── Scale factor ──────────────────────────────────────────────────────────

    private const SCALE = 2.0;

    // ── Public scoring API ────────────────────────────────────────────────────

    /**
     * Compute a normalised risk score [0.0, 100.0] for a single Finding.
     *
     * base = severityWeight * confidenceWeight * SCALE
     * result is clamped then rounded to 2 decimal places.
     */
    public function computeFindingScore(Finding $finding): float
    {
        $base = $this->severityWeight($finding->severity)
              * $this->confidenceWeight($finding->confidence)
              * self::SCALE;

        return round($this->clamp($base), 2);
    }

    /**
     * Compute a blended risk score [0.0, 100.0] for a file given its findings.
     *
     * Algorithm:
     *   1. maxScore  = highest individual finding score
     *   2. avgScore  = mean of all individual finding scores
     *   3. blended   = maxScore * 0.6 + avgScore * 0.4
     *   4. Apply diminishing-returns log factor: blended * min(log2(count+1), 3.0)
     *   5. Clamp to [0.0, 100.0], round to 2 dp.
     *
     * @param Finding[] $findings
     */
    public function computeFileScore(array $findings): float
    {
        if ($findings === []) {
            return 0.0;
        }

        $scores = array_map([$this, 'computeFindingScore'], $findings);
        $count  = count($scores);

        $maxScore  = max($scores);
        $avgScore  = array_sum($scores) / $count;
        $blended   = $maxScore * 0.6 + $avgScore * 0.4;

        $logFactor = min(log($count + 1, 2), 3.0);
        $result    = $blended * $logFactor;

        return round($this->clamp($result), 2);
    }

    /**
     * Compute a weighted overall risk score [0.0, 100.0] from an array of
     * FileResult objects.
     *
     * Weighting: sort descending by riskScore; top file weight=3, second=2,
     * all remaining files weight=1.
     *
     * @param FileResult[] $fileResults
     */
    public function computeOverallScore(array $fileResults): float
    {
        if ($fileResults === []) {
            return 0.0;
        }

        // Sort descending by riskScore (copy to avoid mutating caller's array).
        $sorted = $fileResults;
        usort($sorted, static fn(FileResult $a, FileResult $b): int =>
            $b->riskScore <=> $a->riskScore
        );

        $weightedSum   = 0.0;
        $weightedCount = 0;

        foreach ($sorted as $index => $fr) {
            $weight = match ($index) {
                0 => 3,
                1 => 2,
                default => 1,
            };

            $weightedSum   += $fr->riskScore * $weight;
            $weightedCount += $weight;
        }

        $overall = $weightedSum / $weightedCount;

        return round($this->clamp($overall), 2);
    }

    /**
     * Build FileResult objects from raw per-file data, score them, then return
     * the array sorted descending by riskScore.
     *
     * Each element of $fileResultsWithFindings must contain:
     *   'filePath'    => string
     *   'relativePath'=> string
     *   'findings'    => Finding[]
     *   'iocs'        => IOC[]
     *   'wpContext'   => ?WPContext
     *   'scanTimeMs'  => float
     *
     * @param  array<int, array{filePath: string, relativePath: string, findings: Finding[], iocs: IOC[], wpContext: ?WPContext, scanTimeMs: float}> $fileResultsWithFindings
     * @return FileResult[]
     */
    public function scoreAndSortFileResults(array $fileResultsWithFindings): array
    {
        $fileResults = [];

        foreach ($fileResultsWithFindings as $item) {
            $riskScore = $this->computeFileScore($item['findings']);

            $fileResults[] = new FileResult(
                filePath:     $item['filePath'],
                relativePath: $item['relativePath'],
                findings:     $item['findings'],
                iocs:         $item['iocs'],
                riskScore:    $riskScore,
                wpContext:    $item['wpContext'],
                scanTimeMs:   $item['scanTimeMs'],
            );
        }

        usort($fileResults, static fn(FileResult $a, FileResult $b): int =>
            $b->riskScore <=> $a->riskScore
        );

        return $fileResults;
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /**
     * Look up the severity weight for the scoring matrix.
     */
    private function severityWeight(Severity $severity): int
    {
        return self::SEVERITY_WEIGHT[$severity->value];
    }

    /**
     * Look up the confidence weight for the scoring matrix.
     */
    private function confidenceWeight(Confidence $confidence): int
    {
        return self::CONFIDENCE_WEIGHT[$confidence->value];
    }

    /**
     * Clamp a float value to the inclusive range [0.0, 100.0].
     */
    private function clamp(float $value): float
    {
        return max(0.0, min(100.0, $value));
    }
}
