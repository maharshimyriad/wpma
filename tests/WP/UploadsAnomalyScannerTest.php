<?php

declare(strict_types=1);

namespace Wpma\Tests\WP;

use PHPUnit\Framework\TestCase;
use Wpma\Config\ScanConfig;
use Wpma\Detectors\BackdoorDetector;
use Wpma\Engine\RiskEngine;
use Wpma\Engine\ScanOrchestrator;
use Wpma\Pipeline\PipelineRunner;
use Wpma\WP\UploadsAnomalyScanner;

final class UploadsAnomalyScannerTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tmpDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'wpma-uploads-' . bin2hex(random_bytes(6));
        mkdir($this->tmpDir, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeDirectory($this->tmpDir);
        parent::tearDown();
    }

    public function testEmptyPhpInUploadsIsMediumWarning(): void
    {
        $file = $this->createUploadsFile('empty.php', "");

        $finding = $this->singleUploadsFinding($file);

        $this->assertSame('UPLD-001', $finding->ruleId);
        $this->assertSame('medium', $finding->severity->value);
        $this->assertSame('high', $finding->confidence->value);
    }

    public function testSilenceIsGoldenPhpInUploadsIsMediumWarning(): void
    {
        $file = $this->createUploadsFile('index.php', "<?php\n// Silence is golden.\n");

        $finding = $this->singleUploadsFinding($file);

        $this->assertSame('UPLD-001', $finding->ruleId);
        $this->assertSame('medium', $finding->severity->value);
    }

    public function testHeaderOnly404PhpInUploadsIsMediumWarning(): void
    {
        $file = $this->createUploadsFile(
            'deny.php',
            "<?php\nheader( \$_SERVER['SERVER_PROTOCOL'] . ' 404 Not Found' );\nheader( 'Status: 404 Not Found' );\n"
        );

        $finding = $this->singleUploadsFinding($file);

        $this->assertSame('UPLD-001', $finding->ruleId);
        $this->assertSame('medium', $finding->severity->value);
    }

    public function testBenignPhpCodeInUploadsIsMediumWarning(): void
    {
        $file = $this->createUploadsFile('placeholder.php', "<?php\necho 'ok';\n");

        $finding = $this->singleUploadsFinding($file);

        $this->assertSame('UPLD-001', $finding->ruleId);
        $this->assertSame('medium', $finding->severity->value);
    }

    public function testMaliciousRequestControlledSystemPhpInUploadsPreservesBehavioralFinding(): void
    {
        $siteRoot = $this->createWordPressSiteRoot('malicious-site');
        $uploadsDir = $siteRoot . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'uploads';
        mkdir($uploadsDir . DIRECTORY_SEPARATOR . '2026' . DIRECTORY_SEPARATOR . '08', 0777, true);
        $file = $uploadsDir . DIRECTORY_SEPARATOR . '2026' . DIRECTORY_SEPARATOR . '08' . DIRECTORY_SEPARATOR . 'shell.php';
        file_put_contents($file, "<?php\nsystem(\$_GET['cmd'] ?? '');\n");

        $fileList = $this->tmpDir . DIRECTORY_SEPARATOR . 'files.txt';
        $suspiciousList = $this->tmpDir . DIRECTORY_SEPARATOR . 'suspicious.txt';
        file_put_contents($fileList, $file . PHP_EOL);
        file_put_contents($suspiciousList, $file . PHP_EOL);

        $config = new ScanConfig(
            target: $uploadsDir,
            showProgress: false,
            targetType: \Wpma\Cli\ScanTargetType::UPLOADS_DIRECTORY,
        );

        $orchestrator = new ScanOrchestrator(
            config: $config,
            detectors: [new BackdoorDetector()],
            fileListPath: $fileList,
            suspiciousListPath: $suspiciousList,
        );

        $report = $orchestrator->scan();
        $this->assertNotEmpty($report->fileResults);

        $ruleIds = [];
        foreach ($report->fileResults[0]->findings as $finding) {
            $ruleIds[] = $finding->ruleId;
        }

        $this->assertContains('BACK-001', $ruleIds);
        $this->assertContains('UPLD-001', $ruleIds);

        $back001 = array_values(array_filter($report->fileResults[0]->findings, static fn ($f): bool => $f->ruleId === 'BACK-001'));
        $this->assertNotEmpty($back001);
        $this->assertSame('high', $back001[0]->severity->value);
    }

    public function testUncommonExecutableExtensionInUploadsUsesUploadsPhpRule(): void
    {
        $file = $this->createUploadsFile('shell.pht', "<?php\n\n");

        $finding = $this->singleUploadsFinding($file);

        $this->assertSame('UPLD-001', $finding->ruleId);
        $this->assertSame('medium', $finding->severity->value);
    }

    public function testPhpMagicBytesDetectionRemainsNoteworthy(): void
    {
        $file = $this->createUploadsFile('payload.bin', "<?php echo 'x';");

        $finding = $this->singleUploadsFinding($file);

        $this->assertSame('UPLD-001', $finding->ruleId);
    }

    private function singleUploadsFinding(string $file): \Wpma\Models\Finding
    {
        $scanner = new UploadsAnomalyScanner();
        $results = $scanner->scan($this->uploadsRootFor($file));

        $normalizedFile = str_replace('\\', '/', $file);
        $normalizedResults = [];
        foreach ($results as $path => $findings) {
            $normalizedResults[str_replace('\\', '/', $path)] = $findings;
        }

        $this->assertArrayHasKey($normalizedFile, $normalizedResults);
        $this->assertCount(1, $normalizedResults[$normalizedFile]);

        return $normalizedResults[$normalizedFile][0];
    }

    private function createUploadsFile(string $relativeName, string $content): string
    {
        $uploadsDir = $this->tmpDir . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . '2026' . DIRECTORY_SEPARATOR . '08';
        mkdir($uploadsDir, 0777, true);
        $file = $uploadsDir . DIRECTORY_SEPARATOR . $relativeName;
        file_put_contents($file, $content);

        return $file;
    }

    private function uploadsRootFor(string $file): string
    {
        return dirname(dirname($file));
    }

    private function createWordPressSiteRoot(string $name): string
    {
        $root = $this->tmpDir . DIRECTORY_SEPARATOR . $name;
        mkdir($root . DIRECTORY_SEPARATOR . 'wp-admin', 0777, true);
        mkdir($root . DIRECTORY_SEPARATOR . 'wp-includes', 0777, true);
        mkdir($root . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'plugins', 0777, true);
        mkdir($root . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'themes', 0777, true);
        file_put_contents($root . DIRECTORY_SEPARATOR . 'wp-config.php', "<?php\n");

        return $root;
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
