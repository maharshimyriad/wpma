<?php

declare(strict_types=1);

namespace Wpma\Tests\Engine;

use PHPUnit\Framework\TestCase;
use Wpma\Cli\ScanTargetType;
use Wpma\Config\ScanConfig;
use Wpma\Engine\ScanOrchestrator;
use Wpma\WP\PluginIntegrity;
use Wpma\WP\PluginIntegrityChecker;
use Wpma\WP\WpCoreIntegrityChecker;

final class ScanOrchestratorRoutingTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tmpDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'wpma-routing-' . bin2hex(random_bytes(6));
        mkdir($this->tmpDir, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeDirectory($this->tmpDir);
        parent::tearDown();
    }

    public function testSinglePluginRunsOnlyPluginIntegrity(): void
    {
        $pluginDir = $this->createWordPressSiteWithPlugin('wordfence');
        $pluginFile = $pluginDir . DIRECTORY_SEPARATOR . 'wordfence.php';
        file_put_contents($pluginFile, "<?php echo 'plugin';\n");

        [$report, $pluginChecker, $coreChecker] = $this->runScan(
            target: $pluginDir,
            targetType: ScanTargetType::SINGLE_PLUGIN,
            files: [$pluginFile],
        );

        $this->assertCount(1, $pluginChecker->calls);
        $this->assertCount(0, $coreChecker->calls);
        $this->assertArrayHasKey('wordfence', $report->pluginIntegrity);
        $this->assertArrayNotHasKey('core', $report->pluginIntegrity);
    }

    public function testSingleThemeRunsNoCoreOrPluginIntegrity(): void
    {
        $themeDir = $this->createWordPressSiteWithTheme('bb-theme-child');
        $themeFile = $themeDir . DIRECTORY_SEPARATOR . 'functions.php';
        file_put_contents($themeFile, "<?php echo 'theme';\n");

        [$report, $pluginChecker, $coreChecker] = $this->runScan(
            target: $themeDir,
            targetType: ScanTargetType::SINGLE_THEME,
            files: [$themeFile],
        );

        $this->assertCount(0, $pluginChecker->calls);
        $this->assertCount(0, $coreChecker->calls);
        $this->assertSame([], $report->pluginIntegrity);
    }

    public function testSingleFileRunsNoSiteWideIntegrity(): void
    {
        $siteRoot = $this->createWordPressSiteRoot('single-file-site');
        $file = $siteRoot . DIRECTORY_SEPARATOR . 'wp-config.php';
        file_put_contents($file, "<?php define('DB_NAME', 'test');\n");

        [$report, $pluginChecker, $coreChecker] = $this->runScan(
            target: $file,
            targetType: ScanTargetType::SINGLE_FILE,
            files: [$file],
        );

        $this->assertCount(0, $pluginChecker->calls);
        $this->assertCount(0, $coreChecker->calls);
        $this->assertSame([], $report->pluginIntegrity);
    }

    public function testUploadsDirectoryRunsNoCoreOrPluginIntegrity(): void
    {
        $siteRoot = $this->createWordPressSiteRoot('uploads-site');
        $uploadsDir = $siteRoot . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'uploads';
        mkdir($uploadsDir . DIRECTORY_SEPARATOR . '2026' . DIRECTORY_SEPARATOR . '08', 0777, true);
        $file = $uploadsDir . DIRECTORY_SEPARATOR . '2026' . DIRECTORY_SEPARATOR . '08' . DIRECTORY_SEPARATOR . 'shell.php';
        file_put_contents($file, "<?php echo 'upload';\n");

        [$report, $pluginChecker, $coreChecker] = $this->runScan(
            target: $uploadsDir,
            targetType: ScanTargetType::UPLOADS_DIRECTORY,
            files: [$file],
        );

        $this->assertCount(0, $pluginChecker->calls);
        $this->assertCount(0, $coreChecker->calls);
        $this->assertArrayNotHasKey('core', $report->pluginIntegrity);
    }

    public function testGenericDirectoryIsNotTreatedAsPlugin(): void
    {
        $dir = $this->tmpDir . DIRECTORY_SEPARATOR . 'wpma-test-generic';
        mkdir($dir, 0777, true);
        $file = $dir . DIRECTORY_SEPARATOR . 'sample.php';
        file_put_contents($file, "<?php echo 'generic';\n");

        [$report, $pluginChecker, $coreChecker] = $this->runScan(
            target: $dir,
            targetType: ScanTargetType::GENERIC_DIRECTORY,
            files: [$file],
        );

        $this->assertCount(0, $pluginChecker->calls);
        $this->assertCount(0, $coreChecker->calls);
        $this->assertSame([], $report->pluginIntegrity);
    }

    public function testWordPressCoreTargetRunsOnlyCoreIntegrity(): void
    {
        $coreRoot = $this->tmpDir . DIRECTORY_SEPARATOR . 'core-root';
        mkdir($coreRoot . DIRECTORY_SEPARATOR . 'wp-admin', 0777, true);
        mkdir($coreRoot . DIRECTORY_SEPARATOR . 'wp-includes', 0777, true);
        $file = $coreRoot . DIRECTORY_SEPARATOR . 'wp-includes' . DIRECTORY_SEPARATOR . 'version.php';
        file_put_contents($file, "<?php\n");

        [$report, $pluginChecker, $coreChecker] = $this->runScan(
            target: $coreRoot,
            targetType: ScanTargetType::WORDPRESS_CORE,
            files: [$file],
        );

        $this->assertCount(0, $pluginChecker->calls);
        $this->assertCount(1, $coreChecker->calls);
        $this->assertArrayHasKey('core', $report->pluginIntegrity);
    }

    /**
     * @param string[] $files
     * @return array{0: \Wpma\Models\ScanReport, 1: FakePluginIntegrityChecker, 2: FakeCoreIntegrityChecker}
     */
    private function runScan(string $target, ScanTargetType $targetType, array $files): array
    {
        $fileList = $this->tmpDir . DIRECTORY_SEPARATOR . 'files.txt';
        $suspiciousList = $this->tmpDir . DIRECTORY_SEPARATOR . 'suspicious.txt';
        file_put_contents($fileList, implode(PHP_EOL, $files));
        file_put_contents($suspiciousList, implode(PHP_EOL, $files));

        $pluginChecker = new FakePluginIntegrityChecker();
        $coreChecker = new FakeCoreIntegrityChecker();

        $config = new ScanConfig(
            target: $target,
            showProgress: false,
            targetType: $targetType,
        );

        $orchestrator = new ScanOrchestrator(
            config: $config,
            detectors: [],
            fileListPath: $fileList,
            suspiciousListPath: $suspiciousList,
            integrityChecker: $pluginChecker,
            coreChecker: $coreChecker,
        );

        return [$orchestrator->scan(), $pluginChecker, $coreChecker];
    }

    private function createWordPressSiteWithPlugin(string $slug): string
    {
        $root = $this->createWordPressSiteRoot('plugin-site-' . $slug);
        $pluginDir = $root . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'plugins' . DIRECTORY_SEPARATOR . $slug;
        mkdir($pluginDir, 0777, true);

        return $pluginDir;
    }

    private function createWordPressSiteWithTheme(string $slug): string
    {
        $root = $this->createWordPressSiteRoot('theme-site-' . $slug);
        $themeDir = $root . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'themes' . DIRECTORY_SEPARATOR . $slug;
        mkdir($themeDir, 0777, true);

        return $themeDir;
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

final class FakePluginIntegrityChecker extends PluginIntegrityChecker
{
    /** @var array<int, array{pluginDir: string, wpRoot: string}> */
    public array $calls = [];

    public function check(string $pluginDir, string $wpRoot = ''): PluginIntegrity
    {
        $this->calls[] = ['pluginDir' => $pluginDir, 'wpRoot' => $wpRoot];

        return new PluginIntegrity(
            status: PluginIntegrity::UNAVAILABLE,
            slug: basename(str_replace('\\', '/', $pluginDir)),
            version: '',
            modifiedFiles: [],
            unexpectedFiles: [],
            missingFiles: [],
            method: 'fake',
        );
    }
}

final class FakeCoreIntegrityChecker extends WpCoreIntegrityChecker
{
    /** @var string[] */
    public array $calls = [];

    public function check(string $wpRoot): PluginIntegrity
    {
        $this->calls[] = $wpRoot;

        return new PluginIntegrity(
            status: PluginIntegrity::UNAVAILABLE,
            slug: 'core',
            version: '',
            modifiedFiles: [],
            unexpectedFiles: [],
            missingFiles: [],
            method: 'fake-core',
        );
    }
}
