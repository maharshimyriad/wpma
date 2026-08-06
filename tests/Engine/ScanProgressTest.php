<?php

declare(strict_types=1);

namespace Wpma\Tests\Engine;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use Wpma\Cli\ScanTargetType;
use Wpma\Config\ScanConfig;
use Wpma\Engine\ScanOrchestrator;
use Wpma\Engine\ScanPlan;
use Wpma\Engine\ScanProgress;
use Wpma\Engine\TerminalActivityIndicator;

final class ScanProgressTest extends TestCase
{
    public function testQuietModeDisablesProgressOutput(): void
    {
        $output = '';
        $config = new ScanConfig('/wp', showProgress: false, targetType: ScanTargetType::WORDPRESS_SITE);
        $progress = new ScanProgress($config, ScanPlan::forConfig($config), static function (string $chunk) use (&$output): void {
            $output .= $chunk;
        }, false);

        $progress->beginCoreIntegrity();
        $progress->finishCoreIntegrity();
        $progress->beginMalwareAnalysis();
        $progress->updateMalwareProgress(1, 10, '/wp/index.php');
        $progress->completeMalwareAnalysis();

        $this->assertSame('', $output);
    }

    public function testNonInteractiveOutputDoesNotUseCarriageReturnsForAnalysisProgress(): void
    {
        $output = '';
        $config = new ScanConfig('/wp', showProgress: true, noColor: true, targetType: ScanTargetType::GENERIC_DIRECTORY);
        $progress = new ScanProgress($config, ScanPlan::forConfig($config), static function (string $chunk) use (&$output): void {
            $output .= $chunk;
        }, false);

        $progress->beginMalwareAnalysis();
        $progress->updateMalwareProgress(1, 4, '/wp/a.php');
        $progress->completeMalwareAnalysis();

        $this->assertStringNotContainsString("\r", $output);
        $this->assertStringContainsString('Malware analysis', $output);
    }

    public function testNoColorProgressContainsNoAnsiCodes(): void
    {
        $output = '';
        $config = new ScanConfig('/wp', showProgress: true, noColor: true, targetType: ScanTargetType::WORDPRESS_SITE);
        $progress = new ScanProgress($config, ScanPlan::forConfig($config), static function (string $chunk) use (&$output): void {
            $output .= $chunk;
        }, false);

        $progress->beginCoreIntegrity();
        $progress->finishCoreIntegrity();

        $this->assertStringNotContainsString("\033[", $output);
        $this->assertStringContainsString('3/5', $output);
    }

    public function testInteractiveAnalysisUsesKnownTotalProgress(): void
    {
        $output = '';
        $config = new ScanConfig('/wp', showProgress: true, targetType: ScanTargetType::GENERIC_DIRECTORY);
        $progress = new ScanProgress($config, ScanPlan::forConfig($config), static function (string $chunk) use (&$output): void {
            $output .= $chunk;
        }, true);

        $progress->beginMalwareAnalysis();
        $progress->updateMalwareProgress(50, 100, '/wp/file.php');

        $this->assertStringContainsString('[50/100 50%]', $output);
    }

    public function testPatternFilteringUsesAccurateCandidateWording(): void
    {
        $output = '';
        $config = new ScanConfig('/wp', showProgress: true, noColor: true, targetType: ScanTargetType::GENERIC_DIRECTORY);
        $progress = new ScanProgress($config, ScanPlan::forConfig($config), static function (string $chunk) use (&$output): void {
            $output .= $chunk;
        }, false);

        $progress->beginPatternFiltering();
        $progress->completePatternFiltering(12, 90);

        $this->assertStringContainsString('12 suspicious candidate(s) identified from 90 PHP file(s)', $output);
    }

    public function testEmptyDirectoryRemovesPatternFilteringFromVisiblePlan(): void
    {
        $output = '';
        $config = new ScanConfig('/tmp/empty', showProgress: true, noColor: true, targetType: ScanTargetType::GENERIC_DIRECTORY);
        $progress = new ScanProgress($config, ScanPlan::forConfig($config), static function (string $chunk) use (&$output): void {
            $output .= $chunk;
        }, false);

        $progress->beginFileDiscovery();
        $progress->completeFileDiscovery(0);
        $progress->beginMalwareAnalysis();
        $progress->completeMalwareAnalysis();

        $this->assertStringContainsString('1/2  Indexing PHP files...', $output);
        $this->assertStringContainsString('2/2  Malware analysis', $output);
        $this->assertStringNotContainsString('Pattern filtering', $output);
        $this->assertStringNotContainsString('2/3', $output);
        $this->assertStringNotContainsString('3/3', $output);
        $this->assertContiguousStageNumbers($output);
        $this->assertLastStageCompletesPlan($output);
    }

    public function testShellRenderedEmptyDiscoveryStillRenumbersMalwareStage(): void
    {
        $output = '';
        $tmpDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'wpma-progress-' . bin2hex(random_bytes(6));
        mkdir($tmpDir, 0777, true);

        try {
            $fileList = $tmpDir . DIRECTORY_SEPARATOR . 'files.txt';
            $suspiciousList = $tmpDir . DIRECTORY_SEPARATOR . 'suspicious.txt';
            file_put_contents($fileList, '');
            file_put_contents($suspiciousList, '');

            $config = new ScanConfig(
                target: $tmpDir,
                showProgress: true,
                noColor: true,
                targetType: ScanTargetType::GENERIC_DIRECTORY,
            );
            $progress = new ScanProgress($config, ScanPlan::forConfig($config), static function (string $chunk) use (&$output): void {
                $output .= $chunk;
            }, false);

            $orchestrator = new ScanOrchestrator(
                config: $config,
                detectors: [],
                fileListPath: $fileList,
                suspiciousListPath: $suspiciousList,
                progress: $progress,
            );

            $orchestrator->scan();
            $progress->completeMalwareAnalysis();

            $this->assertStringContainsString('2/2  Malware analysis', $output);
            $this->assertStringNotContainsString('3/3  Malware analysis', $output);
            $this->assertStringNotContainsString('Pattern filtering', $output);
            $this->assertLastStageCompletesPlan($output);
        } finally {
            @unlink($fileList ?? '');
            @unlink($suspiciousList ?? '');
            @rmdir($tmpDir);
        }
    }

    public function testGenericDirectoryWithPhpKeepsThreeVisibleStages(): void
    {
        $output = '';
        $config = new ScanConfig('/tmp/generic', showProgress: true, noColor: true, targetType: ScanTargetType::GENERIC_DIRECTORY);
        $progress = new ScanProgress($config, ScanPlan::forConfig($config), static function (string $chunk) use (&$output): void {
            $output .= $chunk;
        }, false);

        $progress->beginFileDiscovery();
        $progress->completeFileDiscovery(1);
        $progress->beginPatternFiltering();
        $progress->completePatternFiltering(1, 1);
        $progress->beginMalwareAnalysis();
        $progress->completeMalwareAnalysis();

        $this->assertStringContainsString('1/3  Indexing PHP files...', $output);
        $this->assertStringContainsString('2/3  Pattern filtering...', $output);
        $this->assertStringContainsString('3/3  Malware analysis', $output);
        $this->assertContiguousStageNumbers($output);
        $this->assertLastStageCompletesPlan($output);
    }

    public function testZeroCandidatesStillKeepsPatternFilteringStage(): void
    {
        $output = '';
        $config = new ScanConfig('/wp/wp-config.php', showProgress: true, noColor: true, targetType: ScanTargetType::SINGLE_FILE);
        $progress = new ScanProgress($config, ScanPlan::forConfig($config), static function (string $chunk) use (&$output): void {
            $output .= $chunk;
        }, false);

        $progress->beginFileDiscovery();
        $progress->completeFileDiscovery(1);
        $progress->beginPatternFiltering();
        $progress->completePatternFiltering(0, 1);
        $progress->beginMalwareAnalysis();
        $progress->completeMalwareAnalysis();

        $this->assertStringContainsString('2/3  Pattern filtering...', $output);
        $this->assertStringContainsString('0 suspicious candidate(s) identified from 1 PHP file(s)', $output);
        $this->assertContiguousStageNumbers($output);
        $this->assertLastStageCompletesPlan($output);
    }

    public function testSinglePluginKeepsContiguousFourStagePlan(): void
    {
        $output = '';
        $config = new ScanConfig('/wp/wp-content/plugins/wordfence', showProgress: true, noColor: true, targetType: ScanTargetType::SINGLE_PLUGIN);
        $progress = new ScanProgress($config, ScanPlan::forConfig($config), static function (string $chunk) use (&$output): void {
            $output .= $chunk;
        }, false);

        $progress->beginFileDiscovery();
        $progress->completeFileDiscovery(610);
        $progress->beginPatternFiltering();
        $progress->completePatternFiltering(12, 610);
        $progress->beginPluginIntegrity();
        $progress->completePluginIntegrity(1);
        $progress->beginMalwareAnalysis();
        $progress->completeMalwareAnalysis();

        $this->assertStringContainsString('1/4  Indexing PHP files...', $output);
        $this->assertStringContainsString('2/4  Pattern filtering...', $output);
        $this->assertStringContainsString('3/4  Checking plugin integrity', $output);
        $this->assertStringContainsString('4/4  Malware analysis', $output);
        $this->assertContiguousStageNumbers($output);
        $this->assertLastStageCompletesPlan($output);
    }

    public function testSingleFileProgressDoesNotMentionLargeDirectory(): void
    {
        $output = '';
        $config = new ScanConfig('/wp/wp-config.php', showProgress: true, noColor: true, targetType: ScanTargetType::SINGLE_FILE);
        $progress = new ScanProgress($config, ScanPlan::forConfig($config), static function (string $chunk) use (&$output): void {
            $output .= $chunk;
        }, false);

        $progress->beginMalwareAnalysis();

        $this->assertStringContainsString('Malware analysis', $output);
        $this->assertStringNotContainsString('Large directory', $output);
    }

    public function testCoreIntegrityActivityUsesStaticMessageOutsideTty(): void
    {
        $output = '';
        $config = new ScanConfig('/wp', showProgress: true, noColor: true, targetType: ScanTargetType::WORDPRESS_SITE);
        $progress = new ScanProgress($config, ScanPlan::forConfig($config), static function (string $chunk) use (&$output): void {
            $output .= $chunk;
        }, false);

        $progress->beginCoreIntegrity();
        $progress->finishCoreIntegrity();

        $this->assertStringContainsString('Checking WordPress core integrity', $output);
        $this->assertStringContainsString('Checking WordPress.org integrity...', $output);
        $this->assertStringNotContainsString("\r", $output);
    }

    public function testProgressHandlesPathsWithSpaces(): void
    {
        $output = '';
        $config = new ScanConfig('/c/Users/admin/Desktop/shell wp/wpma', showProgress: true, noColor: true, targetType: ScanTargetType::GENERIC_DIRECTORY);
        $progress = new ScanProgress($config, ScanPlan::forConfig($config), static function (string $chunk) use (&$output): void {
            $output .= $chunk;
        }, false);

        $progress->beginMalwareAnalysis();
        $progress->updateMalwareProgress(1, 2, '/c/Users/admin/Desktop/shell wp/wpma/suspicious file.php');
        $progress->completeMalwareAnalysis();

        $this->assertStringContainsString('suspicious file.php', $output);
    }

    public function testProgressSupportsMsysAndWindowsPaths(): void
    {
        $msysOutput = '';
        $windowsOutput = '';

        $msysConfig = new ScanConfig('/c/xampp/htdocs/public_html/wp-content/plugins/wordfence', showProgress: true, noColor: true, targetType: ScanTargetType::SINGLE_PLUGIN);
        $windowsConfig = new ScanConfig('C:\\xampp\\htdocs\\public_html\\wp-content\\plugins\\wordfence', showProgress: true, noColor: true, targetType: ScanTargetType::SINGLE_PLUGIN);

        $msysProgress = new ScanProgress($msysConfig, ScanPlan::forConfig($msysConfig), static function (string $chunk) use (&$msysOutput): void {
            $msysOutput .= $chunk;
        }, false);
        $windowsProgress = new ScanProgress($windowsConfig, ScanPlan::forConfig($windowsConfig), static function (string $chunk) use (&$windowsOutput): void {
            $windowsOutput .= $chunk;
        }, false);

        $msysProgress->beginPluginIntegrity();
        $windowsProgress->beginPluginIntegrity();

        $this->assertStringContainsString('3/4', $msysOutput);
        $this->assertStringContainsString('3/4', $windowsOutput);
    }

    public function testActivityIndicatorFramesUseFixedWidthSlot(): void
    {
        $widths = array_map(static fn (string $frame): int => strlen($frame), TerminalActivityIndicator::frames());

        $this->assertSame([3, 3, 3], $widths);
        $this->assertSame(['.  ', '.. ', '...'], TerminalActivityIndicator::frames());
    }

    public function testActivityIndicatorStopsAndCleansUpInteractiveProcess(): void
    {
        if (!function_exists('proc_open')) {
            self::markTestSkipped('proc_open is not available.');
        }

        $output = '';
        $indicator = new TerminalActivityIndicator(
            enabled: true,
            interactive: true,
            writer: static function (string $chunk) use (&$output): void {
                $output .= $chunk;
            },
        );

        $indicator->start('Checking plugin integrity');
        usleep(100000);
        $indicator->stop();

        $reflection = new ReflectionClass($indicator);
        $proc = $reflection->getProperty('proc');
        $proc->setAccessible(true);
        $sentinel = $reflection->getProperty('sentinelPath');
        $sentinel->setAccessible(true);

        $this->assertNull($proc->getValue($indicator));
        $this->assertNull($sentinel->getValue($indicator));
    }

    private function assertContiguousStageNumbers(string $output): void
    {
        $stages = $this->extractStageNumbers($output);
        $currents = array_column($stages, 0);
        $totals = array_column($stages, 1);

        self::assertNotSame([], $stages);
        self::assertSame(range(1, count($currents)), $currents);
        self::assertCount(1, array_unique($totals));
    }

    private function assertLastStageCompletesPlan(string $output): void
    {
        $stages = $this->extractStageNumbers($output);
        $last = $stages[array_key_last($stages)];

        self::assertSame($last[1], $last[0]);
    }

    /** @return list<array{0:int,1:int}> */
    private function extractStageNumbers(string $output): array
    {
        preg_match_all('/^\s*(\d+)\/(\d+)\s+/m', $output, $matches, PREG_SET_ORDER);

        return array_map(
            static fn (array $match): array => [(int) $match[1], (int) $match[2]],
            $matches,
        );
    }
}
