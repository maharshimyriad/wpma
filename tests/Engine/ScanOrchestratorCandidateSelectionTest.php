<?php

declare(strict_types=1);

namespace Wpma\Tests\Engine;

use PHPUnit\Framework\TestCase;
use Wpma\Cli\ScanTargetType;
use Wpma\Config\ScanConfig;
use Wpma\Detectors\DetectorInterface;
use Wpma\Engine\ScanOrchestrator;
use Wpma\Models\AnalysisObject;
use Wpma\Models\Confidence;
use Wpma\Models\DetectionCategory;
use Wpma\Models\Finding;
use Wpma\Models\Severity;
use Wpma\WP\PluginIntegrity;
use Wpma\WP\PluginIntegrityChecker;
use Wpma\WP\WpCoreIntegrityChecker;

final class ScanOrchestratorCandidateSelectionTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tmpDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'wpma-candidates-' . bin2hex(random_bytes(6));
        mkdir($this->tmpDir, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeDirectory($this->tmpDir);
        parent::tearDown();
    }

    public function testVerifiedPluginFilesAreSkippedInSmartMode(): void
    {
        $pluginDir = $this->createPlugin('verified-plugin', [
            'verified-plugin.php' => "<?php echo 'main';\n",
            'helper.php' => "<?php echo 'helper';\n",
        ]);

        $report = $this->runPluginScan(
            pluginDir: $pluginDir,
            discoveredFiles: [
                $pluginDir . DIRECTORY_SEPARATOR . 'verified-plugin.php',
                $pluginDir . DIRECTORY_SEPARATOR . 'helper.php',
            ],
            suspiciousFiles: [
                $pluginDir . DIRECTORY_SEPARATOR . 'verified-plugin.php',
                $pluginDir . DIRECTORY_SEPARATOR . 'helper.php',
            ],
            integrity: new PluginIntegrity(
                status: PluginIntegrity::VERIFIED,
                slug: 'verified-plugin',
                version: '1.0.0',
                method: 'fake',
                officialCount: 2,
                localCount: 2,
                okCount: 2,
            ),
        );

        $this->assertSame(0, $report->filesScanned);
    }

    public function testUnexpectedPluginFileIsAnalyzedButOfficialFilesAreSkipped(): void
    {
        $pluginDir = $this->createPlugin('wordfence', [
            'wordfence.php' => "<?php echo 'main';\n",
            'lib.php' => "<?php echo 'helper';\n",
            'injected.php' => "<?php echo 'extra';\n",
        ]);

        $report = $this->runPluginScan(
            pluginDir: $pluginDir,
            discoveredFiles: [
                $pluginDir . DIRECTORY_SEPARATOR . 'wordfence.php',
                $pluginDir . DIRECTORY_SEPARATOR . 'lib.php',
                $pluginDir . DIRECTORY_SEPARATOR . 'injected.php',
            ],
            suspiciousFiles: [
                $pluginDir . DIRECTORY_SEPARATOR . 'wordfence.php',
                $pluginDir . DIRECTORY_SEPARATOR . 'lib.php',
                $pluginDir . DIRECTORY_SEPARATOR . 'injected.php',
            ],
            integrity: new PluginIntegrity(
                status: PluginIntegrity::MODIFIED,
                slug: 'wordfence',
                version: '8.2.2',
                modifiedFiles: [],
                unexpectedFiles: ['injected.php'],
                missingFiles: [],
                method: 'fake',
                officialCount: 2,
                localCount: 3,
                okCount: 2,
            ),
        );

        $this->assertSame(1, $report->filesScanned);
        $this->assertCount(1, $report->fileResults);
        $this->assertStringEndsWith('injected.php', $report->fileResults[0]->filePath);
    }

    public function testModifiedOfficialFileIsAnalyzedEvenWhenNotPreFiltered(): void
    {
        $pluginDir = $this->createPlugin('modified-plugin', [
            'modified-plugin.php' => "<?php echo 'main';\n",
            'helper.php' => "<?php echo 'helper';\n",
        ]);

        $report = $this->runPluginScan(
            pluginDir: $pluginDir,
            discoveredFiles: [
                $pluginDir . DIRECTORY_SEPARATOR . 'modified-plugin.php',
                $pluginDir . DIRECTORY_SEPARATOR . 'helper.php',
            ],
            suspiciousFiles: [],
            integrity: new PluginIntegrity(
                status: PluginIntegrity::MODIFIED,
                slug: 'modified-plugin',
                version: '1.0.0',
                modifiedFiles: ['modified-plugin.php'],
                unexpectedFiles: [],
                missingFiles: [],
                method: 'fake',
                officialCount: 2,
                localCount: 2,
                okCount: 1,
            ),
        );

        $this->assertSame(1, $report->filesScanned);
        $this->assertCount(1, $report->fileResults);
        $this->assertStringEndsWith('modified-plugin.php', $report->fileResults[0]->filePath);
    }

    public function testUnavailableSinglePluginScanStillUsesMalwareCandidates(): void
    {
        $pluginDir = $this->createPlugin('custom-plugin', [
            'custom-plugin.php' => "<?php echo 'main';\n",
            'other.php' => "<?php echo 'other';\n",
        ]);

        $integrity = new PluginIntegrity(
            status: PluginIntegrity::UNAVAILABLE,
            slug: 'custom-plugin',
            version: '1.0.0',
        );

        $report = $this->runPluginScan(
            pluginDir: $pluginDir,
            discoveredFiles: [
                $pluginDir . DIRECTORY_SEPARATOR . 'custom-plugin.php',
                $pluginDir . DIRECTORY_SEPARATOR . 'other.php',
            ],
            suspiciousFiles: [
                $pluginDir . DIRECTORY_SEPARATOR . 'other.php',
            ],
            integrity: $integrity,
        );

        $this->assertSame(1, $report->filesScanned);

        $selection = $this->invokeSmartSelection(
            pluginDir: $pluginDir,
            discoveredFiles: [
                $pluginDir . DIRECTORY_SEPARATOR . 'custom-plugin.php',
                $pluginDir . DIRECTORY_SEPARATOR . 'other.php',
            ],
            suspiciousFiles: [
                $pluginDir . DIRECTORY_SEPARATOR . 'other.php',
            ],
            integrity: $integrity,
        );

        $this->assertSame(0, $selection['integritySkippedCount']);
        $this->assertCount(1, $selection['files']);
    }

    public function testFullModeOverridesSmartCandidateSkipping(): void
    {
        $pluginDir = $this->createPlugin('full-mode-plugin', [
            'full-mode-plugin.php' => "<?php echo 'main';\n",
            'helper.php' => "<?php echo 'helper';\n",
            'injected.php' => "<?php echo 'extra';\n",
        ]);

        $report = $this->runPluginScan(
            pluginDir: $pluginDir,
            discoveredFiles: [
                $pluginDir . DIRECTORY_SEPARATOR . 'full-mode-plugin.php',
                $pluginDir . DIRECTORY_SEPARATOR . 'helper.php',
                $pluginDir . DIRECTORY_SEPARATOR . 'injected.php',
            ],
            suspiciousFiles: [
                $pluginDir . DIRECTORY_SEPARATOR . 'full-mode-plugin.php',
                $pluginDir . DIRECTORY_SEPARATOR . 'helper.php',
                $pluginDir . DIRECTORY_SEPARATOR . 'injected.php',
            ],
            integrity: new PluginIntegrity(
                status: PluginIntegrity::MODIFIED,
                slug: 'full-mode-plugin',
                version: '1.0.0',
                modifiedFiles: [],
                unexpectedFiles: ['injected.php'],
                missingFiles: [],
                method: 'fake',
                officialCount: 2,
                localCount: 3,
                okCount: 2,
            ),
            fullMode: true,
        );

        $this->assertSame(3, $report->filesScanned);
    }

    public function testVerifiedCoreFilesAreSkippedInSmartMode(): void
    {
        $siteRoot = $this->createWordPressSite([
            'wp-includes/ID3/getid3.lib.php' => "<?php echo 'core';\n",
        ]);

        $report = $this->runSiteScan(
            siteRoot: $siteRoot,
            discoveredFiles: [
                $siteRoot . DIRECTORY_SEPARATOR . 'wp-includes' . DIRECTORY_SEPARATOR . 'ID3' . DIRECTORY_SEPARATOR . 'getid3.lib.php',
            ],
            suspiciousFiles: [
                $siteRoot . DIRECTORY_SEPARATOR . 'wp-includes' . DIRECTORY_SEPARATOR . 'ID3' . DIRECTORY_SEPARATOR . 'getid3.lib.php',
            ],
            coreIntegrity: new PluginIntegrity(
                status: PluginIntegrity::VERIFIED,
                slug: 'core',
                version: '7.0',
                method: 'fake-core',
                officialCount: 1,
                localCount: 1,
                okCount: 1,
                verifiedFiles: ['wp-includes/ID3/getid3.lib.php'],
            ),
        );

        $this->assertSame(0, $report->filesScanned);
    }

    public function testVerifiedCoreFilesAreSkippedInSmartModeForWordPressCoreTarget(): void
    {
        $siteRoot = $this->createWordPressSite([
            'wp-includes/ID3/getid3.lib.php' => "<?php echo 'core';\n",
        ]);

        $report = $this->runSiteScan(
            siteRoot: $siteRoot,
            discoveredFiles: [
                $siteRoot . DIRECTORY_SEPARATOR . 'wp-includes' . DIRECTORY_SEPARATOR . 'ID3' . DIRECTORY_SEPARATOR . 'getid3.lib.php',
            ],
            suspiciousFiles: [
                $siteRoot . DIRECTORY_SEPARATOR . 'wp-includes' . DIRECTORY_SEPARATOR . 'ID3' . DIRECTORY_SEPARATOR . 'getid3.lib.php',
            ],
            coreIntegrity: new PluginIntegrity(
                status: PluginIntegrity::VERIFIED,
                slug: 'core',
                version: '7.0',
                method: 'fake-core',
                officialCount: 1,
                localCount: 1,
                okCount: 1,
                verifiedFiles: ['wp-includes/ID3/getid3.lib.php'],
            ),
            targetType: ScanTargetType::WORDPRESS_CORE,
        );

        $this->assertSame(0, $report->filesScanned);
    }

    public function testWordPressCoreTargetDoesNotScanPluginFiles(): void
    {
        $siteRoot = $this->createWordPressSite([
            'wp-includes/ID3/getid3.lib.php' => "<?php echo 'core';\n",
            'wp-content/plugins/example/example.php' => "<?php echo 'plugin';\n",
        ]);

        $report = $this->runSiteScan(
            siteRoot: $siteRoot,
            discoveredFiles: [
                $siteRoot . DIRECTORY_SEPARATOR . 'wp-includes' . DIRECTORY_SEPARATOR . 'ID3' . DIRECTORY_SEPARATOR . 'getid3.lib.php',
                $siteRoot . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'plugins' . DIRECTORY_SEPARATOR . 'example' . DIRECTORY_SEPARATOR . 'example.php',
            ],
            suspiciousFiles: [
                $siteRoot . DIRECTORY_SEPARATOR . 'wp-includes' . DIRECTORY_SEPARATOR . 'ID3' . DIRECTORY_SEPARATOR . 'getid3.lib.php',
                $siteRoot . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'plugins' . DIRECTORY_SEPARATOR . 'example' . DIRECTORY_SEPARATOR . 'example.php',
            ],
            coreIntegrity: new PluginIntegrity(
                status: PluginIntegrity::VERIFIED,
                slug: 'core',
                version: '7.0',
                method: 'fake-core',
                officialCount: 1,
                localCount: 1,
                okCount: 1,
                verifiedFiles: ['wp-includes/ID3/getid3.lib.php'],
            ),
            targetType: ScanTargetType::WORDPRESS_CORE,
        );

        $this->assertSame(0, $report->filesScanned);
        $this->assertSame([], $report->fileResults);
    }

    public function testModifiedCoreFileIsAnalyzedInSmartMode(): void
    {
        $siteRoot = $this->createWordPressSite([
            'wp-includes/version.php' => "<?php echo 'modified core';\n",
        ]);

        $report = $this->runSiteScan(
            siteRoot: $siteRoot,
            discoveredFiles: [
                $siteRoot . DIRECTORY_SEPARATOR . 'wp-includes' . DIRECTORY_SEPARATOR . 'version.php',
            ],
            suspiciousFiles: [],
            coreIntegrity: new PluginIntegrity(
                status: PluginIntegrity::MODIFIED,
                slug: 'core',
                version: '7.0',
                modifiedFiles: ['wp-includes/version.php'],
                unexpectedFiles: [],
                missingFiles: [],
                method: 'fake-core',
                officialCount: 1,
                localCount: 1,
                okCount: 0,
                verifiedFiles: [],
            ),
        );

        $this->assertSame(1, $report->filesScanned);
        $this->assertCount(1, $report->fileResults);
        $this->assertStringEndsWith('wp-includes/version.php', str_replace('\\', '/', $report->fileResults[0]->filePath));
    }

    public function testUnexpectedCoreFileIsAnalyzedInSmartMode(): void
    {
        $siteRoot = $this->createWordPressSite([
            'wp-includes/evil.php' => "<?php echo 'evil';\n",
        ]);

        $report = $this->runSiteScan(
            siteRoot: $siteRoot,
            discoveredFiles: [
                $siteRoot . DIRECTORY_SEPARATOR . 'wp-includes' . DIRECTORY_SEPARATOR . 'evil.php',
            ],
            suspiciousFiles: [],
            coreIntegrity: new PluginIntegrity(
                status: PluginIntegrity::MODIFIED,
                slug: 'core',
                version: '7.0',
                modifiedFiles: [],
                unexpectedFiles: ['wp-includes/evil.php'],
                missingFiles: [],
                method: 'fake-core',
                officialCount: 0,
                localCount: 1,
                okCount: 0,
                verifiedFiles: [],
            ),
        );

        $this->assertSame(1, $report->filesScanned);
        $this->assertCount(1, $report->fileResults);
        $this->assertStringEndsWith('wp-includes/evil.php', str_replace('\\', '/', $report->fileResults[0]->filePath));
    }

    public function testVerifiedCoreSelectionNormalizesWindowsPaths(): void
    {
        $selection = $this->invokeCoreSmartSelection(
            targetRoot: 'C:/xampp/htdocs/wordpress',
            discoveredFiles: [
                'C:\\xampp\\htdocs\\wordpress\\wp-includes\\functions.php',
                'C:/xampp/htdocs/wordpress/wp-admin/includes/class-wp-filesystem-direct.php',
            ],
            suspiciousFiles: [
                'C:/xampp/htdocs/wordpress/wp-includes/functions.php',
                'C:\\xampp\\htdocs\\wordpress\\wp-admin\\includes\\class-wp-filesystem-direct.php',
            ],
            coreIntegrity: new PluginIntegrity(
                status: PluginIntegrity::VERIFIED,
                slug: 'core',
                version: '7.0',
                method: 'fake-core',
                officialCount: 2,
                localCount: 2,
                okCount: 2,
                verifiedFiles: [
                    'wp-includes/functions.php',
                    'wp-admin/includes/class-wp-filesystem-direct.php',
                ],
            ),
            verifiedCoreRoot: 'C:\\xampp\\htdocs\\wordpress',
        );

        $this->assertSame([], $selection['files']);
        $this->assertSame(2, $selection['integritySkippedCount']);
    }

    public function testVerifiedCoreSelectionNormalizesGitBashPaths(): void
    {
        $selection = $this->invokeCoreSmartSelection(
            targetRoot: 'C:/xampp/htdocs/wordpress',
            discoveredFiles: [
                '/c/xampp/htdocs/wordpress/wp-includes/ID3/getid3.lib.php',
                '/c/xampp/htdocs/wordpress/wp-includes/PHPMailer/PHPMailer.php',
            ],
            suspiciousFiles: [
                'C:/xampp/htdocs/wordpress/wp-includes/ID3/getid3.lib.php',
                'C:/xampp/htdocs/wordpress/wp-includes/PHPMailer/PHPMailer.php',
            ],
            coreIntegrity: new PluginIntegrity(
                status: PluginIntegrity::VERIFIED,
                slug: 'core',
                version: '7.0',
                method: 'fake-core',
                officialCount: 2,
                localCount: 2,
                okCount: 2,
                verifiedFiles: [
                    'wp-includes/ID3/getid3.lib.php',
                    'wp-includes/PHPMailer/PHPMailer.php',
                ],
            ),
            verifiedCoreRoot: '/c/xampp/htdocs/wordpress',
        );

        $this->assertSame([], $selection['files']);
        $this->assertSame(2, $selection['integritySkippedCount']);
    }

    public function testUnavailablePluginIsSkippedDuringNormalPluginsDirectoryScan(): void
    {
        $pluginsDir = $this->createPluginsDirectorySite([
            'verified-plugin' => [
                'verified-plugin.php' => "<?php echo 'verified';\n",
            ],
            'bb-plugin' => [
                'bb-plugin.php' => "<?php echo 'bb';\n",
                'suspicious.php' => "<?php eval('bad');\n",
            ],
        ]);

        $report = $this->runPluginsDirectoryScan(
            pluginsDir: $pluginsDir,
            discoveredFiles: [
                $pluginsDir . DIRECTORY_SEPARATOR . 'verified-plugin' . DIRECTORY_SEPARATOR . 'verified-plugin.php',
                $pluginsDir . DIRECTORY_SEPARATOR . 'bb-plugin' . DIRECTORY_SEPARATOR . 'bb-plugin.php',
                $pluginsDir . DIRECTORY_SEPARATOR . 'bb-plugin' . DIRECTORY_SEPARATOR . 'suspicious.php',
            ],
            suspiciousFiles: [
                $pluginsDir . DIRECTORY_SEPARATOR . 'verified-plugin' . DIRECTORY_SEPARATOR . 'verified-plugin.php',
                $pluginsDir . DIRECTORY_SEPARATOR . 'bb-plugin' . DIRECTORY_SEPARATOR . 'suspicious.php',
            ],
            integrities: [
                'verified-plugin' => new PluginIntegrity(
                    status: PluginIntegrity::VERIFIED,
                    slug: 'verified-plugin',
                    version: '1.0.0',
                    method: 'fake',
                    officialCount: 1,
                    localCount: 1,
                    okCount: 1,
                ),
                'bb-plugin' => new PluginIntegrity(
                    status: PluginIntegrity::UNAVAILABLE,
                    slug: 'bb-plugin',
                    version: '2.10.3.1',
                ),
            ],
        );

        $this->assertSame(0, $report->filesScanned);
        $this->assertSame([], $report->fileResults);
        $this->assertSame(0.0, $report->overallRiskScore);
        $this->assertTrue($report->pluginIntegrity['bb-plugin']['malwareAnalysisSkipped']);
        $this->assertFalse($report->pluginIntegrity['bb-plugin']['officialSourceAvailable']);
    }

    public function testPluginsDirectoryMixedScanAppliesPerPluginIntegritySelection(): void
    {
        $pluginsDir = $this->createPluginsDirectorySite([
            'verified-plugin' => [
                'verified-plugin.php' => "<?php echo 'verified';\n",
                'helper.php' => "<?php echo 'verified helper';\n",
            ],
            'modified-plugin' => [
                'modified-plugin.php' => "<?php echo 'modified';\n",
                'helper.php' => "<?php echo 'modified helper';\n",
            ],
            'mailchimp' => [
                'mailchimp.php' => "<?php echo 'mailchimp';\n",
                'license.php' => "<?php echo 'license';\n",
            ],
            'bb-plugin' => [
                'bb-plugin.php' => "<?php echo 'bb';\n",
                'custom.php' => "<?php echo 'custom';\n",
            ],
        ]);

        $report = $this->runPluginsDirectoryScan(
            pluginsDir: $pluginsDir,
            discoveredFiles: [
                $pluginsDir . DIRECTORY_SEPARATOR . 'verified-plugin' . DIRECTORY_SEPARATOR . 'verified-plugin.php',
                $pluginsDir . DIRECTORY_SEPARATOR . 'verified-plugin' . DIRECTORY_SEPARATOR . 'helper.php',
                $pluginsDir . DIRECTORY_SEPARATOR . 'modified-plugin' . DIRECTORY_SEPARATOR . 'modified-plugin.php',
                $pluginsDir . DIRECTORY_SEPARATOR . 'modified-plugin' . DIRECTORY_SEPARATOR . 'helper.php',
                $pluginsDir . DIRECTORY_SEPARATOR . 'mailchimp' . DIRECTORY_SEPARATOR . 'mailchimp.php',
                $pluginsDir . DIRECTORY_SEPARATOR . 'mailchimp' . DIRECTORY_SEPARATOR . 'license.php',
                $pluginsDir . DIRECTORY_SEPARATOR . 'bb-plugin' . DIRECTORY_SEPARATOR . 'bb-plugin.php',
                $pluginsDir . DIRECTORY_SEPARATOR . 'bb-plugin' . DIRECTORY_SEPARATOR . 'custom.php',
            ],
            suspiciousFiles: [
                $pluginsDir . DIRECTORY_SEPARATOR . 'verified-plugin' . DIRECTORY_SEPARATOR . 'verified-plugin.php',
                $pluginsDir . DIRECTORY_SEPARATOR . 'verified-plugin' . DIRECTORY_SEPARATOR . 'helper.php',
                $pluginsDir . DIRECTORY_SEPARATOR . 'modified-plugin' . DIRECTORY_SEPARATOR . 'modified-plugin.php',
                $pluginsDir . DIRECTORY_SEPARATOR . 'modified-plugin' . DIRECTORY_SEPARATOR . 'helper.php',
                $pluginsDir . DIRECTORY_SEPARATOR . 'mailchimp' . DIRECTORY_SEPARATOR . 'mailchimp.php',
                $pluginsDir . DIRECTORY_SEPARATOR . 'mailchimp' . DIRECTORY_SEPARATOR . 'license.php',
                $pluginsDir . DIRECTORY_SEPARATOR . 'bb-plugin' . DIRECTORY_SEPARATOR . 'custom.php',
            ],
            integrities: [
                'verified-plugin' => new PluginIntegrity(
                    status: PluginIntegrity::VERIFIED,
                    slug: 'verified-plugin',
                    version: '1.0.0',
                    method: 'fake',
                    officialCount: 2,
                    localCount: 2,
                    okCount: 2,
                ),
                'modified-plugin' => new PluginIntegrity(
                    status: PluginIntegrity::MODIFIED,
                    slug: 'modified-plugin',
                    version: '1.0.0',
                    modifiedFiles: ['modified-plugin.php'],
                    unexpectedFiles: [],
                    missingFiles: [],
                    method: 'fake',
                    officialCount: 2,
                    localCount: 2,
                    okCount: 1,
                ),
                'mailchimp' => new PluginIntegrity(
                    status: PluginIntegrity::MODIFIED,
                    slug: 'mailchimp',
                    version: '1.0.0',
                    modifiedFiles: [],
                    unexpectedFiles: ['license.php'],
                    missingFiles: [],
                    method: 'fake',
                    officialCount: 1,
                    localCount: 2,
                    okCount: 1,
                ),
                'bb-plugin' => new PluginIntegrity(
                    status: PluginIntegrity::UNAVAILABLE,
                    slug: 'bb-plugin',
                    version: '2.10.3.1',
                ),
            ],
        );

        $this->assertSame(2, $report->filesScanned);
        $scannedPaths = array_map(static fn ($fr): string => str_replace('\\', '/', $fr->filePath), $report->fileResults);
        sort($scannedPaths);

        $this->assertContains(str_replace('\\', '/', $pluginsDir . DIRECTORY_SEPARATOR . 'modified-plugin' . DIRECTORY_SEPARATOR . 'modified-plugin.php'), $scannedPaths);
        $this->assertContains(str_replace('\\', '/', $pluginsDir . DIRECTORY_SEPARATOR . 'mailchimp' . DIRECTORY_SEPARATOR . 'license.php'), $scannedPaths);
        $this->assertNotContains(str_replace('\\', '/', $pluginsDir . DIRECTORY_SEPARATOR . 'bb-plugin' . DIRECTORY_SEPARATOR . 'custom.php'), $scannedPaths);
        $this->assertNotContains(str_replace('\\', '/', $pluginsDir . DIRECTORY_SEPARATOR . 'verified-plugin' . DIRECTORY_SEPARATOR . 'verified-plugin.php'), $scannedPaths);
        $this->assertNotContains(str_replace('\\', '/', $pluginsDir . DIRECTORY_SEPARATOR . 'verified-plugin' . DIRECTORY_SEPARATOR . 'helper.php'), $scannedPaths);
        $this->assertNotContains(str_replace('\\', '/', $pluginsDir . DIRECTORY_SEPARATOR . 'modified-plugin' . DIRECTORY_SEPARATOR . 'helper.php'), $scannedPaths);
        $this->assertNotContains(str_replace('\\', '/', $pluginsDir . DIRECTORY_SEPARATOR . 'mailchimp' . DIRECTORY_SEPARATOR . 'mailchimp.php'), $scannedPaths);
        $this->assertTrue($report->pluginIntegrity['bb-plugin']['malwareAnalysisSkipped']);
    }

    /**
     * @param string[] $discoveredFiles
     * @param string[] $suspiciousFiles
     */
    private function runPluginScan(
        string $pluginDir,
        array $discoveredFiles,
        array $suspiciousFiles,
        PluginIntegrity $integrity,
        bool $fullMode = false,
    ): \Wpma\Models\ScanReport {
        $fileList = $this->tmpDir . DIRECTORY_SEPARATOR . 'files-' . bin2hex(random_bytes(4)) . '.txt';
        $suspiciousList = $this->tmpDir . DIRECTORY_SEPARATOR . 'suspicious-' . bin2hex(random_bytes(4)) . '.txt';
        file_put_contents($fileList, implode(PHP_EOL, $discoveredFiles));
        file_put_contents($suspiciousList, implode(PHP_EOL, $suspiciousFiles));

        $config = new ScanConfig(
            target: $pluginDir,
            fullMode: $fullMode,
            showProgress: false,
            targetType: ScanTargetType::SINGLE_PLUGIN,
        );

        $checker = new CandidateSelectionFakePluginIntegrityChecker([$integrity->slug => $integrity]);

        $orchestrator = new ScanOrchestrator(
            config: $config,
            detectors: [],
            fileListPath: $fileList,
            suspiciousListPath: $suspiciousList,
            integrityChecker: $checker,
        );

        try {
            return $orchestrator->scan();
        } finally {
            @unlink($fileList);
            @unlink($suspiciousList);
        }
    }

    /**
     * @param string[] $discoveredFiles
     * @param string[] $suspiciousFiles
     * @return array{files: list<string>, integritySkippedCount: int}
     */
    private function invokeSmartSelection(
        string $pluginDir,
        array $discoveredFiles,
        array $suspiciousFiles,
        PluginIntegrity $integrity,
    ): array {
        $config = new ScanConfig(
            target: $pluginDir,
            showProgress: false,
            targetType: ScanTargetType::SINGLE_PLUGIN,
        );

        $orchestrator = new ScanOrchestrator(
            config: $config,
            detectors: [],
            integrityChecker: new CandidateSelectionFakePluginIntegrityChecker([$integrity->slug => $integrity]),
        );

        $reflection = new \ReflectionClass($orchestrator);
        $resultsProp = $reflection->getProperty('pluginIntegrityResults');
        $resultsProp->setValue($orchestrator, [$integrity->slug => $integrity]);

        $method = $reflection->getMethod('selectMalwareAnalysisFiles');
        $method->setAccessible(true);

        /** @var array{files: list<string>, integritySkippedCount: int} $selection */
        $selection = $method->invoke($orchestrator, $discoveredFiles, $suspiciousFiles);

        return $selection;
    }

    /**
     * @param string[] $discoveredFiles
     * @param string[] $suspiciousFiles
     * @return array{files: list<string>, integritySkippedCount: int}
     */
    private function invokeCoreSmartSelection(
        string $targetRoot,
        array $discoveredFiles,
        array $suspiciousFiles,
        PluginIntegrity $coreIntegrity,
        string $verifiedCoreRoot,
    ): array {
        $config = new ScanConfig(
            target: $targetRoot,
            showProgress: false,
            targetType: ScanTargetType::WORDPRESS_CORE,
        );

        $orchestrator = new ScanOrchestrator(
            config: $config,
            detectors: [],
        );

        $reflection = new \ReflectionClass($orchestrator);
        $resultsProp = $reflection->getProperty('pluginIntegrityResults');
        $resultsProp->setValue($orchestrator, ['core' => $coreIntegrity]);
        $coreRootProp = $reflection->getProperty('verifiedCoreRoot');
        $coreRootProp->setValue($orchestrator, $verifiedCoreRoot);

        $method = $reflection->getMethod('selectMalwareAnalysisFiles');
        $method->setAccessible(true);

        /** @var array{files: list<string>, integritySkippedCount: int} $selection */
        $selection = $method->invoke($orchestrator, $discoveredFiles, $suspiciousFiles);

        return $selection;
    }

    /**
     * @param string[] $discoveredFiles
     * @param string[] $suspiciousFiles
     * @param array<string, PluginIntegrity> $integrities
     */
    private function runSiteScan(
        string $siteRoot,
        array $discoveredFiles,
        array $suspiciousFiles,
        PluginIntegrity $coreIntegrity,
        bool $fullMode = false,
        ScanTargetType $targetType = ScanTargetType::WORDPRESS_SITE,
    ): \Wpma\Models\ScanReport {
        $fileList = $this->tmpDir . DIRECTORY_SEPARATOR . 'site-files-' . bin2hex(random_bytes(4)) . '.txt';
        $suspiciousList = $this->tmpDir . DIRECTORY_SEPARATOR . 'site-suspicious-' . bin2hex(random_bytes(4)) . '.txt';
        file_put_contents($fileList, implode(PHP_EOL, $discoveredFiles));
        file_put_contents($suspiciousList, implode(PHP_EOL, $suspiciousFiles));

        $config = new ScanConfig(
            target: $siteRoot,
            fullMode: $fullMode,
            showProgress: false,
            targetType: $targetType,
        );

        $orchestrator = new ScanOrchestrator(
            config: $config,
            detectors: [new AlwaysFindingDetector()],
            fileListPath: $fileList,
            suspiciousListPath: $suspiciousList,
            coreChecker: new CandidateSelectionFakeCoreIntegrityChecker($coreIntegrity),
        );

        try {
            return $orchestrator->scan();
        } finally {
            @unlink($fileList);
            @unlink($suspiciousList);
        }
    }

    /**
     * @param string[] $discoveredFiles
     * @param string[] $suspiciousFiles
     * @param array<string, PluginIntegrity> $integrities
     */
    private function runPluginsDirectoryScan(
        string $pluginsDir,
        array $discoveredFiles,
        array $suspiciousFiles,
        array $integrities,
    ): \Wpma\Models\ScanReport {
        $fileList = $this->tmpDir . DIRECTORY_SEPARATOR . 'plugins-files-' . bin2hex(random_bytes(4)) . '.txt';
        $suspiciousList = $this->tmpDir . DIRECTORY_SEPARATOR . 'plugins-suspicious-' . bin2hex(random_bytes(4)) . '.txt';
        file_put_contents($fileList, implode(PHP_EOL, $discoveredFiles));
        file_put_contents($suspiciousList, implode(PHP_EOL, $suspiciousFiles));

        $config = new ScanConfig(
            target: $pluginsDir,
            showProgress: false,
            targetType: ScanTargetType::PLUGINS_DIRECTORY,
        );

        $orchestrator = new ScanOrchestrator(
            config: $config,
            detectors: [new AlwaysFindingDetector()],
            fileListPath: $fileList,
            suspiciousListPath: $suspiciousList,
            integrityChecker: new CandidateSelectionFakePluginIntegrityChecker($integrities),
        );

        try {
            return $orchestrator->scan();
        } finally {
            @unlink($fileList);
            @unlink($suspiciousList);
        }
    }

    /**
     * @param array<string, string> $files
     */
    private function createWordPressSite(array $files): string
    {
        $siteRoot = $this->tmpDir . DIRECTORY_SEPARATOR . 'core-site-' . bin2hex(random_bytes(4));
        mkdir($siteRoot . DIRECTORY_SEPARATOR . 'wp-admin', 0777, true);
        mkdir($siteRoot . DIRECTORY_SEPARATOR . 'wp-includes', 0777, true);
        mkdir($siteRoot . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'plugins', 0777, true);
        mkdir($siteRoot . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'themes', 0777, true);
        file_put_contents($siteRoot . DIRECTORY_SEPARATOR . 'wp-config.php', "<?php\n");

        foreach ($files as $relative => $contents) {
            $path = $siteRoot . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative);
            $dir = dirname($path);
            if (!is_dir($dir)) {
                mkdir($dir, 0777, true);
            }
            file_put_contents($path, $contents);
        }

        return $siteRoot;
    }

    /**
     * @param array<string, array<string, string>> $plugins
     */
    private function createPluginsDirectorySite(array $plugins): string
    {
        $siteRoot = $this->tmpDir . DIRECTORY_SEPARATOR . 'plugins-dir-site';
        $pluginsDir = $siteRoot . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'plugins';
        mkdir($pluginsDir, 0777, true);
        mkdir($siteRoot . DIRECTORY_SEPARATOR . 'wp-admin', 0777, true);
        mkdir($siteRoot . DIRECTORY_SEPARATOR . 'wp-includes', 0777, true);
        mkdir($siteRoot . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'themes', 0777, true);
        file_put_contents($siteRoot . DIRECTORY_SEPARATOR . 'wp-config.php', "<?php\n");

        foreach ($plugins as $slug => $files) {
            $this->createPluginFiles($pluginsDir . DIRECTORY_SEPARATOR . $slug, $files);
        }

        return $pluginsDir;
    }

    /**
     * @param array<string, string> $files
     */
    private function createPlugin(string $slug, array $files): string
    {
        $siteRoot = $this->tmpDir . DIRECTORY_SEPARATOR . 'site-' . $slug;
        $pluginDir = $siteRoot . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'plugins' . DIRECTORY_SEPARATOR . $slug;
        mkdir($siteRoot . DIRECTORY_SEPARATOR . 'wp-admin', 0777, true);
        mkdir($siteRoot . DIRECTORY_SEPARATOR . 'wp-includes', 0777, true);
        mkdir($siteRoot . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'themes', 0777, true);
        file_put_contents($siteRoot . DIRECTORY_SEPARATOR . 'wp-config.php', "<?php\n");

        $this->createPluginFiles($pluginDir, $files);

        return $pluginDir;
    }

    /**
     * @param array<string, string> $files
     */
    private function createPluginFiles(string $pluginDir, array $files): void
    {
        if (!is_dir($pluginDir)) {
            mkdir($pluginDir, 0777, true);
        }

        foreach ($files as $relative => $contents) {
            $path = $pluginDir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative);
            $dir = dirname($path);
            if (!is_dir($dir)) {
                mkdir($dir, 0777, true);
            }
            file_put_contents($path, $contents);
        }
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

final class CandidateSelectionFakePluginIntegrityChecker extends PluginIntegrityChecker
{
    /** @param array<string, PluginIntegrity> $results */
    public function __construct(private readonly array $results) {}

    public function check(string $pluginDir, string $wpRoot = ''): PluginIntegrity
    {
        $slug = basename(str_replace('\\', '/', $pluginDir));

        return $this->results[$slug] ?? new PluginIntegrity(
            status: PluginIntegrity::UNAVAILABLE,
            slug: $slug,
        );
    }
}

final class CandidateSelectionFakeCoreIntegrityChecker extends WpCoreIntegrityChecker
{
    public function __construct(private readonly PluginIntegrity $result) {}

    public function check(string $wpRoot): PluginIntegrity
    {
        return $this->result;
    }
}

final class AlwaysFindingDetector implements DetectorInterface
{
    public function getName(): string
    {
        return 'AlwaysFindingDetector';
    }

    public function getVersion(): string
    {
        return '1.0.0';
    }

    public function getSupportedExtensions(): array
    {
        return ['*'];
    }

    public function detect(AnalysisObject $ao): array
    {
        return [Finding::create([
            'ruleId' => 'TST-001',
            'title' => 'Test finding',
            'filePath' => $ao->meta->filePath,
            'line' => 1,
            'severity' => Severity::LOW,
            'confidence' => Confidence::LOW,
            'category' => DetectionCategory::CUSTOM,
            'description' => 'Test detector marker.',
            'explanation' => 'Used to assert which files reached malware analysis.',
            'remediation' => '',
            'evidence' => [],
            'tags' => ['test-detector'],
        ])];
    }

    public function isApplicable(AnalysisObject $ao): bool
    {
        return true;
    }

    public function safeDetect(AnalysisObject $ao): array
    {
        return $this->detect($ao);
    }
}
