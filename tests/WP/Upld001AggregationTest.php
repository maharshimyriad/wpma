<?php

declare(strict_types=1);

namespace Wpma\Tests\WP;

use PHPUnit\Framework\TestCase;
use Wpma\Cli\ScanTargetType;
use Wpma\Config\ScanConfig;
use Wpma\Detectors\BackdoorDetector;
use Wpma\Engine\RiskEngine;
use Wpma\Engine\ScanOrchestrator;
use Wpma\Models\Finding;
use Wpma\Models\ScanReport;
use Wpma\WP\UploadsAnomalyScanner;

/**
 * Regression tests for UPLD-001 flood-control / aggregation.
 *
 * The rule:
 *   < 4 clean UPLD-001 files → individual per-file findings preserved
 *   ≥ 4 clean UPLD-001 files → single aggregate UPLD-001 finding
 *
 * "Clean" means the file has ONLY an UPLD-001 finding (no co-located behavioral
 * findings). Files with behavioral findings from other detectors are never
 * swallowed by the aggregate.
 */
final class Upld001AggregationTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tmpDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'wpma-agg-' . bin2hex(random_bytes(6));
        mkdir($this->tmpDir, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeDirectory($this->tmpDir);
        parent::tearDown();
    }

    // ── Below-threshold: individual findings preserved ─────────────────────────

    public function test1CleanPhpFileProducesIndividualFinding(): void
    {
        $uploadsDir = $this->makeUploadsDir();
        $this->createPhp($uploadsDir, 'a.php', "<?php\n// silence\n");

        $results = (new UploadsAnomalyScanner())->scan($uploadsDir);

        // Exactly 1 entry, no aggregate tag
        $this->assertCount(1, $results, '1 clean PHP → 1 individual entry');
        $finding = array_values($results)[0][0];
        $this->assertSame('UPLD-001', $finding->ruleId);
        $this->assertNotContains('upld001-aggregate', $finding->tags);
    }

    public function test2CleanPhpFilesProduceTwoIndividualFindings(): void
    {
        $uploadsDir = $this->makeUploadsDir();
        $this->createPhp($uploadsDir, 'a.php', "<?php\n");
        $this->createPhp($uploadsDir, 'b.php', "<?php\n");

        $results = (new UploadsAnomalyScanner())->scan($uploadsDir);

        // Below threshold → no aggregation; entries also tested via aggregate method
        $this->assertCount(2, $results, '2 clean PHP → 2 raw entries from scanner');

        // Verify aggregateCleanUpld001Findings leaves them untouched
        $scanner    = new UploadsAnomalyScanner();
        $aggregated = $scanner->aggregateCleanUpld001Findings($results, $uploadsDir);
        $this->assertCount(2, $aggregated, '2 clean PHP → 2 individual entries after aggregation check');
        foreach ($aggregated as $findings) {
            $this->assertNotContains('upld001-aggregate', $findings[0]->tags);
        }
    }

    public function test3CleanPhpFilesProduceThreeIndividualFindings(): void
    {
        $uploadsDir = $this->makeUploadsDir();
        $this->createPhp($uploadsDir, 'a.php', "<?php\n");
        $this->createPhp($uploadsDir, 'b.php', "<?php\n");
        $this->createPhp($uploadsDir, 'c.php', "<?php\n");

        $results    = (new UploadsAnomalyScanner())->scan($uploadsDir);
        $scanner    = new UploadsAnomalyScanner();
        $aggregated = $scanner->aggregateCleanUpld001Findings($results, $uploadsDir);

        $this->assertCount(3, $aggregated, '3 clean PHP → 3 individual entries');
        foreach ($aggregated as $findings) {
            $this->assertNotContains('upld001-aggregate', $findings[0]->tags);
        }
    }

    // ── At-threshold: aggregate fires ─────────────────────────────────────────

    public function test4CleanPhpFilesProduceOneAggregateFinding(): void
    {
        $uploadsDir = $this->makeUploadsDir();
        $this->createPhp($uploadsDir, 'a.php', "<?php\n");
        $this->createPhp($uploadsDir, 'b.php', "<?php\n");
        $this->createPhp($uploadsDir, 'c.php', "<?php\n");
        $this->createPhp($uploadsDir, 'd.php', "<?php\n");

        $results    = (new UploadsAnomalyScanner())->scan($uploadsDir);
        $scanner    = new UploadsAnomalyScanner();
        $aggregated = $scanner->aggregateCleanUpld001Findings($results, $uploadsDir);

        $this->assertCount(1, $aggregated, '4 clean PHP → exactly 1 aggregate entry');
        $finding = array_values($aggregated)[0][0];
        $this->assertSame('UPLD-001', $finding->ruleId);
        $this->assertContains('upld001-aggregate', $finding->tags, 'aggregate tag must be present');
    }

    public function test20CleanPhpFilesProduceOneAggregateFinding(): void
    {
        $uploadsDir = $this->makeUploadsDir();
        for ($i = 1; $i <= 20; $i++) {
            $this->createPhp($uploadsDir, "file{$i}.php", "<?php\n");
        }

        $results    = (new UploadsAnomalyScanner())->scan($uploadsDir);
        $scanner    = new UploadsAnomalyScanner();
        $aggregated = $scanner->aggregateCleanUpld001Findings($results, $uploadsDir);

        $this->assertCount(1, $aggregated, '20 clean PHP → exactly 1 aggregate entry');
        $finding = array_values($aggregated)[0][0];
        $this->assertContains('upld001-aggregate', $finding->tags);
    }

    // ── Aggregate contains correct count ──────────────────────────────────────

    public function testAggregateContainsTotalCount(): void
    {
        $uploadsDir = $this->makeUploadsDir();
        for ($i = 1; $i <= 6; $i++) {
            $this->createPhp($uploadsDir, "f{$i}.php", "<?php\n");
        }

        $scanner    = new UploadsAnomalyScanner();
        $results    = $scanner->scan($uploadsDir);
        $aggregated = $scanner->aggregateCleanUpld001Findings($results, $uploadsDir);
        $finding    = array_values($aggregated)[0][0];

        $this->assertStringContainsString('6', $finding->title, 'Title must contain total count (6)');
        $this->assertStringContainsString('6', $finding->description, 'Description must contain total count (6)');
    }

    // ── Aggregate shows at most 3 representative paths ────────────────────────

    public function testAggregateShowsAtMost3RepresentativePaths(): void
    {
        $uploadsDir = $this->makeUploadsDir();
        for ($i = 1; $i <= 6; $i++) {
            $this->createPhp($uploadsDir, "file{$i}.php", "<?php\n");
        }

        $scanner    = new UploadsAnomalyScanner();
        $results    = $scanner->scan($uploadsDir);
        $aggregated = $scanner->aggregateCleanUpld001Findings($results, $uploadsDir);
        $finding    = array_values($aggregated)[0][0];

        // Count how many "  - " path lines appear in description
        $pathLineCount = substr_count($finding->description, "\n  - ");
        $this->assertLessThanOrEqual(3, $pathLineCount, 'At most 3 representative paths in description');
    }

    public function testAggregateContainsAndNMoreWhenOver3Files(): void
    {
        $uploadsDir = $this->makeUploadsDir();
        for ($i = 1; $i <= 6; $i++) {
            $this->createPhp($uploadsDir, "file{$i}.php", "<?php\n");
        }

        $scanner    = new UploadsAnomalyScanner();
        $results    = $scanner->scan($uploadsDir);
        $aggregated = $scanner->aggregateCleanUpld001Findings($results, $uploadsDir);
        $finding    = array_values($aggregated)[0][0];

        $this->assertStringContainsString('... and 3 more', $finding->description, '"... and N more" must appear');
    }

    // ── All affected paths stored in tags ─────────────────────────────────────

    public function testAggregateTagsContainAllAffectedAbsolutePaths(): void
    {
        $uploadsDir = $this->makeUploadsDir();
        for ($i = 1; $i <= 4; $i++) {
            $this->createPhp($uploadsDir, "f{$i}.php", "<?php\n");
        }

        $scanner    = new UploadsAnomalyScanner();
        $results    = $scanner->scan($uploadsDir);
        $aggregated = $scanner->aggregateCleanUpld001Findings($results, $uploadsDir);
        $finding    = array_values($aggregated)[0][0];

        $pathTags = array_filter($finding->tags, static fn(string $t): bool => str_starts_with($t, 'affected-path:'));
        $this->assertCount(4, $pathTags, 'All 4 affected absolute paths must be in tags');
    }

    // ── 5 clean + 1 malicious: clean aggregated, malicious preserved ──────────

    public function test5CleanAnd1MaliciousPhpPreservesmaliciousSeparately(): void
    {
        $siteRoot   = $this->createWordPressSiteRoot('mixed-site');
        $uploadsDir = $siteRoot . '/wp-content/uploads';
        mkdir($uploadsDir . '/2026/01', 0777, true);

        // 5 clean PHP files
        for ($i = 1; $i <= 5; $i++) {
            file_put_contents("{$uploadsDir}/2026/01/clean{$i}.php", "<?php\n// silence\n");
        }

        // 1 malicious PHP file that the BackdoorDetector will flag
        $malFile = "{$uploadsDir}/2026/01/shell.php";
        file_put_contents($malFile, "<?php\nsystem(\$_GET['cmd'] ?? '');\n");

        [$fileList, $suspList] = $this->makeFileLists([$malFile]);

        $config = new ScanConfig(
            target: $uploadsDir,
            showProgress: false,
            targetType: ScanTargetType::UPLOADS_DIRECTORY,
        );

        $orchestrator = new ScanOrchestrator(
            config: $config,
            detectors: [new BackdoorDetector()],
            fileListPath: $fileList,
            suspiciousListPath: $suspList,
        );

        $report = $orchestrator->scan();

        // Must have at least 2 FileResult entries: aggregate (clean) + malicious
        $this->assertGreaterThanOrEqual(2, count($report->fileResults),
            'Must have separate entries for clean aggregate and malicious file');

        // Locate the aggregate finding
        $aggregateFindings = $this->findByTag($report, 'upld001-aggregate');
        $this->assertCount(1, $aggregateFindings, 'Exactly 1 aggregate UPLD-001 finding');

        $aggregate = $aggregateFindings[0];
        $this->assertStringContainsString('5', $aggregate->title,
            'Aggregate title must state count of clean files (5)');

        // Verify malicious file is NOT inside the aggregate
        $pathTags = array_filter($aggregate->tags, static fn(string $t): bool => str_starts_with($t, 'affected-path:'));
        foreach ($pathTags as $tag) {
            $this->assertStringNotContainsString('shell.php', $tag,
                'Malicious shell.php must NOT appear in the clean aggregate path tags');
        }

        // Verify behavioral finding (BACK-001) still exists for the malicious file
        $back001 = $this->findByRule($report, 'BACK-001');
        $this->assertNotEmpty($back001, 'BACK-001 behavioral finding must still be present for malicious file');

        // Verify UPLD-001 for the malicious file is separately reported (not swallowed)
        $upld001ForMal = array_filter(
            $this->findByRule($report, 'UPLD-001'),
            static fn(Finding $f): bool => !in_array('upld001-aggregate', $f->tags, true),
        );
        $this->assertNotEmpty($upld001ForMal, 'Malicious file must still have its own individual UPLD-001');
    }

    // ── Risk scoring: aggregate contributes only once ─────────────────────────

    public function testAggregateContributesOnlyOnceToRiskScoreVsManyIndividual(): void
    {
        // 4 clean files → aggregate (1 finding → lower or equal overall score)
        $uploadsDir4 = $this->makeUploadsDir('agg-risk-4');
        for ($i = 1; $i <= 4; $i++) {
            $this->createPhp($uploadsDir4, "f{$i}.php", "<?php\n");
        }
        $score4 = $this->scoreForUploadsDir($uploadsDir4);

        // 20 clean files → still just 1 aggregate finding (same risk budget)
        $uploadsDir20 = $this->makeUploadsDir('agg-risk-20');
        for ($i = 1; $i <= 20; $i++) {
            $this->createPhp($uploadsDir20, "f{$i}.php", "<?php\n");
        }
        $score20 = $this->scoreForUploadsDir($uploadsDir20);

        // Both produce exactly 1 MEDIUM/HIGH finding; their scores must be equal
        $this->assertSame($score4, $score20,
            '4 clean files and 20 clean files must yield the same overall risk score (both produce 1 aggregate)');
    }

    // ── Unrelated UPLD rules are not aggregated ────────────────────────────────

    public function testUpld002ArchiveFindingIsNeverAggregated(): void
    {
        $uploadsDir = $this->makeUploadsDir();

        // Create 4 extensionless files that look like ZIP archives (magic bytes PK\x03\x04)
        for ($i = 1; $i <= 4; $i++) {
            $path = $uploadsDir . "/archive{$i}";
            file_put_contents($path, "PK\x03\x04 fake zip content");
        }

        $results = (new UploadsAnomalyScanner())->scan($uploadsDir);

        // UPLD-002 findings must remain individual (not aggregated)
        foreach ($results as $findings) {
            foreach ($findings as $finding) {
                $this->assertNotContains('upld001-aggregate', $finding->tags,
                    'UPLD-002 findings must never receive the aggregate tag');
            }
        }
        $this->assertCount(4, $results, 'UPLD-002 findings remain as 4 individual entries');
    }

    public function testUpld004ScriptFindingIsNeverAggregated(): void
    {
        $uploadsDir = $this->makeUploadsDir();
        for ($i = 1; $i <= 4; $i++) {
            $path = $uploadsDir . "/script{$i}.sh";
            file_put_contents($path, "#!/bin/bash\necho hi\n");
        }

        $results = (new UploadsAnomalyScanner())->scan($uploadsDir);

        foreach ($results as $findings) {
            foreach ($findings as $finding) {
                $this->assertNotContains('upld001-aggregate', $finding->tags,
                    'UPLD-004 findings must never receive the aggregate tag');
            }
        }
        $this->assertCount(4, $results, 'UPLD-004 findings remain as 4 individual entries');
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Create a temp uploads directory (with full WP structure).
     */
    private function makeUploadsDir(string $suffix = 'default'): string
    {
        $uploads = $this->tmpDir . DIRECTORY_SEPARATOR . 'uploads-' . $suffix;
        mkdir($uploads . DIRECTORY_SEPARATOR . '2026' . DIRECTORY_SEPARATOR . '01', 0777, true);
        return str_replace('\\', '/', $uploads);
    }

    /**
     * Write a PHP file inside an uploads directory (in 2026/01/ subfolder).
     */
    private function createPhp(string $uploadsDir, string $name, string $content): string
    {
        $path = $uploadsDir . '/2026/01/' . $name;
        file_put_contents($path, $content);
        return str_replace('\\', '/', $path);
    }

    private function createWordPressSiteRoot(string $name): string
    {
        $root = str_replace('\\', '/', $this->tmpDir . DIRECTORY_SEPARATOR . $name);
        mkdir($root . '/wp-admin', 0777, true);
        mkdir($root . '/wp-includes', 0777, true);
        mkdir($root . '/wp-content/plugins', 0777, true);
        mkdir($root . '/wp-content/themes', 0777, true);
        file_put_contents($root . '/wp-config.php', "<?php\n");
        return $root;
    }

    /**
     * @param  string[] $files
     * @return array{string, string}  [fileListPath, suspiciousListPath]
     */
    private function makeFileLists(array $files): array
    {
        $fileList  = $this->tmpDir . DIRECTORY_SEPARATOR . 'files.txt';
        $suspList  = $this->tmpDir . DIRECTORY_SEPARATOR . 'suspicious.txt';
        file_put_contents($fileList, implode(PHP_EOL, $files));
        file_put_contents($suspList, implode(PHP_EOL, $files));
        return [$fileList, $suspList];
    }

    /**
     * Run a standalone uploads-only scan and return the overall risk score.
     */
    private function scoreForUploadsDir(string $uploadsDir): float
    {
        $config = new ScanConfig(
            target: $uploadsDir,
            showProgress: false,
            targetType: ScanTargetType::UPLOADS_DIRECTORY,
        );

        $tmpFile = $this->tmpDir . '/empty-files.txt';
        file_put_contents($tmpFile, '');

        $orchestrator = new ScanOrchestrator(
            config: $config,
            detectors: [],
            fileListPath: $tmpFile,
            suspiciousListPath: $tmpFile,
        );

        return $orchestrator->scan()->overallRiskScore;
    }

    /** @return Finding[] */
    private function findByTag(ScanReport $report, string $tag): array
    {
        $found = [];
        foreach ($report->fileResults as $fr) {
            foreach ($fr->findings as $f) {
                if (in_array($tag, $f->tags, true)) {
                    $found[] = $f;
                }
            }
        }
        return $found;
    }

    /** @return Finding[] */
    private function findByRule(ScanReport $report, string $ruleId): array
    {
        $found = [];
        foreach ($report->fileResults as $fr) {
            foreach ($fr->findings as $f) {
                if ($f->ruleId === $ruleId) {
                    $found[] = $f;
                }
            }
        }
        return $found;
    }

    private function removeDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $items = scandir($dir);
        if ($items === false) {
            return;
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            if (is_dir($path)) {
                $this->removeDirectory($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }
}
