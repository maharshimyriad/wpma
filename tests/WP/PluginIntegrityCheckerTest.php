<?php

declare(strict_types=1);

namespace Wpma\Tests\WP;

use PHPUnit\Framework\TestCase;
use Wpma\Detectors\PluginIntegrityDetector;
use Wpma\WP\PluginIntegrity;
use Wpma\WP\PluginIntegrityChecker;

/**
 * Tests for PluginIntegrityChecker and PluginIntegrityDetector.
 *
 * Uses a temporary directory tree to simulate plugin installations without
 * requiring network access or a real WordPress installation.
 */
final class PluginIntegrityCheckerTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tmpDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'wpma_integ_' . uniqid('', true);
        mkdir($this->tmpDir, 0755, true);
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->tmpDir);
        parent::tearDown();
    }

    // ── Path normalisation ────────────────────────────────────────────────────

    public function testWindowsBackslashPathNormalisedToForwardSlash(): void
    {
        $checker = new PluginIntegrityChecker();
        $method  = new \ReflectionMethod($checker, 'normalisePath');
        $method->setAccessible(true);

        $this->assertSame(
            'plugin-fw/templates/c',
            $method->invoke($checker, 'plugin-fw\\templates\\c'),
        );
        $this->assertSame(
            'plugin-fw/templates/c',
            $method->invoke($checker, 'plugin-fw/templates/c'),
        );
    }

    public function testWpCliPathNormaliserPreservesUnixPath(): void
    {
        $checker = new PluginIntegrityChecker();
        $method  = new \ReflectionMethod($checker, 'normalisePathForWpCli');
        $method->setAccessible(true);

        $path = '/var/www/html/wp-content/plugins/example';
        $expected = PHP_OS_FAMILY === 'Windows' ? 'C:/var/www/html/wp-content/plugins/example' : $path;

        $this->assertSame($path, $method->invoke($checker, $path));
    }

    public function testWpCliPathNormaliserConvertsMsysPathOnWindows(): void
    {
        $checker = new PluginIntegrityChecker();
        $method  = new \ReflectionMethod($checker, 'normalisePathForWpCli');
        $method->setAccessible(true);

        $expected = PHP_OS_FAMILY === 'Windows'
            ? 'C:/xampp/htdocs/public_html/wp-content/plugins/example'
            : '/c/xampp/htdocs/public_html/wp-content/plugins/example';

        $this->assertSame(
            $expected,
            $method->invoke($checker, '/c/xampp/htdocs/public_html/wp-content/plugins/example'),
        );
    }

    public function testWpCliPathNormaliserConvertsWindowsBackslashes(): void
    {
        $checker = new PluginIntegrityChecker();
        $method  = new \ReflectionMethod($checker, 'normalisePathForWpCli');
        $method->setAccessible(true);

        $this->assertSame(
            'C:/xampp/htdocs/public_html/wp-content/plugins/example',
            $method->invoke($checker, 'C:\\xampp\\htdocs\\public_html\\wp-content\\plugins\\example'),
        );
    }

    public function testWpCliPathNormaliserPreservesSpaces(): void
    {
        $checker = new PluginIntegrityChecker();
        $method  = new \ReflectionMethod($checker, 'normalisePathForWpCli');
        $method->setAccessible(true);

        $path = '/c/Users/admin/Desktop/shell wp/wpma';
        $expected = PHP_OS_FAMILY === 'Windows'
            ? 'C:/Users/admin/Desktop/shell wp/wpma'
            : $path;

        $this->assertSame($expected, $method->invoke($checker, $path));
    }

    public function testBuildWpCliCommandQuotesPathsWithSpaces(): void
    {
        $checker = new PluginIntegrityChecker();
        $method  = new \ReflectionMethod($checker, 'buildWpCliVerifyCommand');
        $method->setAccessible(true);

        $command = $method->invoke($checker, 'example', '/c/Users/admin/AppData/Local/Temp/My Site');

        $expectedPath = PHP_OS_FAMILY === 'Windows'
            ? 'C:/Users/admin/AppData/Local/Temp/My Site'
            : '/c/Users/admin/AppData/Local/Temp/My Site';

        $this->assertStringContainsString('wp --path=', $command);
        $this->assertStringContainsString($expectedPath, $command);
        $this->assertStringContainsString('plugin verify-checksums', $command);
    }

    public function testBuildWpCliCommandUsesPluginIntegrityRootPath(): void
    {
        $checker = new PluginIntegrityChecker();
        $method  = new \ReflectionMethod($checker, 'buildWpCliVerifyCommand');
        $method->setAccessible(true);

        $command = $method->invoke($checker, 'example', 'C:\\xampp\\htdocs\\public_html');

        $this->assertStringContainsString('wp --path=', $command);
        $this->assertStringContainsString('C:/xampp/htdocs/public_html', $command);
        $this->assertStringContainsString('plugin verify-checksums', $command);
        $this->assertStringContainsString('example', $command);
        $this->assertStringEndsWith('2>&1', $command);
    }

    // ── File enumeration (ALL files, no extension filter) ────────────────────

    public function testEnumeratesPhpFiles(): void
    {
        file_put_contents($this->tmpDir . '/plugin.php', '<?php // plugin');

        $checker = new PluginIntegrityChecker();
        $method  = new \ReflectionMethod($checker, 'enumerateAllFiles');
        $method->setAccessible(true);

        $files = $method->invoke($checker, $this->tmpDir);
        $basenames = array_map('basename', $files);

        $this->assertContains('plugin.php', $basenames);
    }

    public function testEnumeratesJsFiles(): void
    {
        file_put_contents($this->tmpDir . '/app.js', 'console.log(1)');

        $checker = new PluginIntegrityChecker();
        $method  = new \ReflectionMethod($checker, 'enumerateAllFiles');
        $method->setAccessible(true);

        $files = $method->invoke($checker, $this->tmpDir);
        $basenames = array_map('basename', $files);

        $this->assertContains('app.js', $basenames);
    }

    public function testEnumeratesExtensionlessFiles(): void
    {
        // Extensionless file — must NOT be skipped
        file_put_contents($this->tmpDir . '/c', 'some content');

        $checker = new PluginIntegrityChecker();
        $method  = new \ReflectionMethod($checker, 'enumerateAllFiles');
        $method->setAccessible(true);

        $files = $method->invoke($checker, $this->tmpDir);
        $basenames = array_map('basename', $files);

        $this->assertContains('c', $basenames, 'Extensionless file must be enumerated');
    }

    public function testEnumeratesNestedExtensionlessFiles(): void
    {
        mkdir($this->tmpDir . '/plugin-fw/templates', 0755, true);
        file_put_contents($this->tmpDir . '/plugin-fw/templates/c', 'nested extensionless');

        $checker = new PluginIntegrityChecker();
        $method  = new \ReflectionMethod($checker, 'enumerateAllFiles');
        $method->setAccessible(true);

        $files = $method->invoke($checker, $this->tmpDir);
        $found = false;
        foreach ($files as $f) {
            if (str_ends_with(str_replace('\\', '/', $f), 'plugin-fw/templates/c')) {
                $found = true;
                break;
            }
        }

        $this->assertTrue($found, 'Nested extensionless file must be enumerated');
    }

    public function testEnumeratesArchiveWithNoExtension(): void
    {
        // Create a fake ZIP archive (PK magic bytes) with no extension
        $zip = "PK\x03\x04" . str_repeat("\x00", 26);
        file_put_contents($this->tmpDir . '/archive_no_ext', $zip);

        $checker = new PluginIntegrityChecker();
        $method  = new \ReflectionMethod($checker, 'enumerateAllFiles');
        $method->setAccessible(true);

        $files    = $method->invoke($checker, $this->tmpDir);
        $basenames = array_map('basename', $files);

        $this->assertContains('archive_no_ext', $basenames);
    }

    // ── File type classification ──────────────────────────────────────────────

    public function testClassifiesZipMagicBytesAsArchive(): void
    {
        $path = $this->tmpDir . '/noext';
        file_put_contents($path, "PK\x03\x04" . str_repeat("\x00", 26));

        $detector = new PluginIntegrityDetector();
        $method   = new \ReflectionMethod($detector, 'classifyFileType');
        $method->setAccessible(true);

        $this->assertSame('archive', $method->invoke($detector, 'noext', $path));
    }

    public function testClassifiesGzipMagicBytesAsArchive(): void
    {
        $path = $this->tmpDir . '/noext';
        file_put_contents($path, "\x1f\x8b" . str_repeat("\x00", 10));

        $detector = new PluginIntegrityDetector();
        $method   = new \ReflectionMethod($detector, 'classifyFileType');
        $method->setAccessible(true);

        $this->assertSame('archive', $method->invoke($detector, 'noext', $path));
    }

    public function testClassifiesPhpOpenTagAsPhp(): void
    {
        $path = $this->tmpDir . '/noext';
        file_put_contents($path, '<?php echo "hello";');

        $detector = new PluginIntegrityDetector();
        $method   = new \ReflectionMethod($detector, 'classifyFileType');
        $method->setAccessible(true);

        $this->assertSame('php', $method->invoke($detector, 'noext', $path));
    }

    public function testClassifiesPhpExtensionAsPhp(): void
    {
        $path = $this->tmpDir . '/plugin.php';
        file_put_contents($path, '<?php');

        $detector = new PluginIntegrityDetector();
        $method   = new \ReflectionMethod($detector, 'classifyFileType');
        $method->setAccessible(true);

        $this->assertSame('php', $method->invoke($detector, 'plugin.php', $path));
    }

    // ── computeChecksumDiff — set arithmetic and hash comparison ─────────────

    public function testComputeChecksumDiffOkFile(): void
    {
        $path = $this->tmpDir . '/plugin.php';
        file_put_contents($path, '<?php // official content');
        $sha256 = hash_file('sha256', $path);

        $checker = new PluginIntegrityChecker();
        $method  = new \ReflectionMethod($checker, 'computeChecksumDiff');
        $method->setAccessible(true);

        $result = $method->invoke(
            $checker,
            ['plugin.php' => $sha256],   // official: one file with matching hash
            ['plugin.php' => $path],     // local: same file on disk
        );

        $this->assertSame(1, $result['okCount'], 'Matching sha256 must increment okCount');
        $this->assertEmpty($result['modified'], 'No modified files expected');
        $this->assertEmpty($result['missing'],  'No missing files expected');
        $this->assertEmpty($result['extra'],    'No extra files expected');
    }

    public function testComputeChecksumDiffModifiedFile(): void
    {
        $path = $this->tmpDir . '/plugin.php';
        file_put_contents($path, '<?php // tampered content');
        // Provide a wrong sha256 (not matching the file content)
        $wrongSha256 = str_repeat('a', 64);

        $checker = new PluginIntegrityChecker();
        $method  = new \ReflectionMethod($checker, 'computeChecksumDiff');
        $method->setAccessible(true);

        $result = $method->invoke(
            $checker,
            ['plugin.php' => $wrongSha256],  // official: wrong hash
            ['plugin.php' => $path],          // local: file exists but content differs
        );

        $this->assertSame(0, $result['okCount']);
        $this->assertContains('plugin.php', $result['modified'], 'Mismatching sha256 must be MODIFIED');
        $this->assertEmpty($result['missing']);
        $this->assertEmpty($result['extra']);
    }

    public function testComputeChecksumDiffMissingFile(): void
    {
        // Official manifest has a file that is NOT present on disk
        $checker = new PluginIntegrityChecker();
        $method  = new \ReflectionMethod($checker, 'computeChecksumDiff');
        $method->setAccessible(true);

        $result = $method->invoke(
            $checker,
            ['includes/missing.php' => str_repeat('a', 64)],   // official: exists
            [],                                                   // local: nothing on disk
        );

        $this->assertSame(0, $result['okCount']);
        $this->assertEmpty($result['modified']);
        $this->assertContains('includes/missing.php', $result['missing'], 'Absent file must be MISSING');
        $this->assertEmpty($result['extra']);
    }

    public function testComputeChecksumDiffExtraFile(): void
    {
        $path = $this->tmpDir . '/injected.php';
        file_put_contents($path, '<?php // injected');

        $checker = new PluginIntegrityChecker();
        $method  = new \ReflectionMethod($checker, 'computeChecksumDiff');
        $method->setAccessible(true);

        $result = $method->invoke(
            $checker,
            [],                               // official: no files
            ['injected.php' => $path],        // local: extra file on disk
        );

        $this->assertSame(0, $result['okCount']);
        $this->assertEmpty($result['modified']);
        $this->assertEmpty($result['missing']);
        $this->assertContains('injected.php', $result['extra'], 'Unlisted local file must be EXTRA');
    }

    public function testComputeChecksumDiffNoSha256FilesNotFlaggedModified(): void
    {
        // Official manifest entry exists but has no sha256 key (null) — must NOT be MODIFIED.
        $path = $this->tmpDir . '/legacy.php';
        file_put_contents($path, '<?php // some content');

        $checker = new PluginIntegrityChecker();
        $method  = new \ReflectionMethod($checker, 'computeChecksumDiff');
        $method->setAccessible(true);

        $result = $method->invoke(
            $checker,
            ['legacy.php' => null],       // official: present but no sha256
            ['legacy.php' => $path],      // local: file exists
        );

        $this->assertNotContains('legacy.php', $result['modified'],
            'File with null sha256 must not be flagged MODIFIED (unverifiable)');
        $this->assertNotContains('legacy.php', $result['missing'],
            'File in official manifest (even without sha256) must not be MISSING when on disk');
        $this->assertNotContains('legacy.php', $result['extra'],
            'File in official manifest must not be EXTRA even without sha256');
        $this->assertSame(1, $result['okCount'],
            'Unverifiable file should still increment okCount');
    }

    // ── Integrity finding generation ──────────────────────────────────────────

    public function testExtraPhpFileGeneratesHighFinding(): void
    {
        $integrity = new PluginIntegrity(
            status:          PluginIntegrity::MODIFIED,
            slug:            'test-plugin',
            version:         '1.0.0',
            modifiedFiles:   [],
            unexpectedFiles: ['injected.php'],
            missingFiles:    [],
            method:          'api',
        );

        $phpPath = $this->tmpDir . '/injected.php';
        file_put_contents($phpPath, '<?php echo 1;');

        $detector = new PluginIntegrityDetector();
        $findings = $detector->generateFindings($integrity, $this->tmpDir);

        $this->assertCount(1, $findings);
        $this->assertSame('INTG-001', $findings[0]->ruleId);
        $this->assertTrue($findings[0]->severity->isAtLeast(\Wpma\Models\Severity::HIGH));
    }

    public function testExtraJsFileGeneratesMediumFinding(): void
    {
        $integrity = new PluginIntegrity(
            status:          PluginIntegrity::MODIFIED,
            slug:            'test-plugin',
            version:         '1.0.0',
            modifiedFiles:   [],
            unexpectedFiles: ['extra.js'],
            missingFiles:    [],
            method:          'api',
        );

        $jsPath = $this->tmpDir . '/extra.js';
        file_put_contents($jsPath, 'var x = 1;');

        $detector = new PluginIntegrityDetector();
        $findings = $detector->generateFindings($integrity, $this->tmpDir);

        $this->assertCount(1, $findings);
        $this->assertSame('INTG-001', $findings[0]->ruleId);
    }

    public function testExtraExtensionlessFileGeneratesFinding(): void
    {
        $integrity = new PluginIntegrity(
            status:          PluginIntegrity::MODIFIED,
            slug:            'test-plugin',
            version:         '1.0.0',
            modifiedFiles:   [],
            unexpectedFiles: ['plugin-fw/templates/c'],
            missingFiles:    [],
            method:          'api',
        );

        mkdir($this->tmpDir . '/plugin-fw/templates', 0755, true);
        $path = $this->tmpDir . '/plugin-fw/templates/c';
        file_put_contents($path, "PK\x03\x04some zip data");

        $detector = new PluginIntegrityDetector();
        $findings = $detector->generateFindings($integrity, $this->tmpDir);

        $this->assertCount(1, $findings);
        $this->assertSame('INTG-001', $findings[0]->ruleId);
        $this->assertStringContainsString('plugin-fw/templates/c', $findings[0]->title);
        // An extensionless ZIP should be CRITICAL
        $this->assertSame(\Wpma\Models\Severity::CRITICAL, $findings[0]->severity);
    }

    public function testModifiedFileGeneratesHighFinding(): void
    {
        $integrity = new PluginIntegrity(
            status:          PluginIntegrity::MODIFIED,
            slug:            'test-plugin',
            version:         '1.0.0',
            modifiedFiles:   ['includes/class-plugin.php'],
            unexpectedFiles: [],
            missingFiles:    [],
            method:          'api',
        );

        mkdir($this->tmpDir . '/includes', 0755, true);
        file_put_contents($this->tmpDir . '/includes/class-plugin.php', '<?php // tampered');

        $detector = new PluginIntegrityDetector();
        $findings = $detector->generateFindings($integrity, $this->tmpDir);

        $this->assertCount(1, $findings);
        $this->assertSame('INTG-002', $findings[0]->ruleId);
        $this->assertSame(\Wpma\Models\Severity::HIGH, $findings[0]->severity);
    }

    public function testMissingPhpFileGeneratesInformationalFinding(): void
    {
        $integrity = new PluginIntegrity(
            status:          PluginIntegrity::MODIFIED,
            slug:            'test-plugin',
            version:         '1.0.0',
            modifiedFiles:   [],
            unexpectedFiles: [],
            missingFiles:    ['readme.txt', 'includes/missing.php'],
            method:          'api',
        );

        $detector = new PluginIntegrityDetector();
        $findings = $detector->generateFindings($integrity, $this->tmpDir);

        // Only missing PHP files generate findings; readme.txt is ignored
        $this->assertCount(1, $findings);
        $this->assertSame('INTG-003', $findings[0]->ruleId);
        $this->assertSame(\Wpma\Models\Severity::INFORMATIONAL, $findings[0]->severity);
    }

    public function testUnavailableIntegrityGeneratesNoFindings(): void
    {
        $integrity = new PluginIntegrity(
            status: PluginIntegrity::UNAVAILABLE,
            slug:   'premium-plugin',
        );

        $detector = new PluginIntegrityDetector();
        $findings = $detector->generateFindings($integrity, $this->tmpDir);

        $this->assertEmpty($findings);
    }

    public function testWpCliOperationalFailureReturnsChecksumUnavailable(): void
    {
        $pluginDir = $this->tmpDir . '/wordfence';
        mkdir($pluginDir, 0755, true);
        file_put_contents($pluginDir . '/wordfence.php', "<?php\n/*\nPlugin Name: Wordfence\nVersion: 8.2.2\n*/\n");

        $checker = new class extends PluginIntegrityChecker {
            protected function httpGetRaw(string $url): array
            {
                return [0, null];
            }

            protected function isWpCliAvailable(): bool
            {
                return true;
            }

            protected function executeCommand(string $cmd): array
            {
                return [1, 'The system cannot find the path specified.'];
            }
        };

        $result = $checker->check($pluginDir, '/c/xampp/htdocs/public_html');

        $this->assertSame(PluginIntegrity::CHECKSUM_UNAVAILABLE, $result->status);
        $this->assertSame('wpcli', $result->method);
    }

    public function testPluginNotOnWordPressOrgDoesNotInvokeWpCliFallback(): void
    {
        $pluginDir = $this->tmpDir . '/custom-plugin';
        mkdir($pluginDir, 0755, true);
        file_put_contents($pluginDir . '/custom-plugin.php', "<?php\n/*\nPlugin Name: Custom Plugin\nVersion: 1.0.0\n*/\n");

        $checker = new class extends PluginIntegrityChecker {
            public int $commandsRun = 0;

            protected function httpGetRaw(string $url): array
            {
                return [404, null];
            }

            protected function isWpCliAvailable(): bool
            {
                return true;
            }

            protected function executeCommand(string $cmd): array
            {
                $this->commandsRun++;
                return [0, ''];
            }
        };

        $result = $checker->check($pluginDir, 'C:/xampp/htdocs/public_html');

        $this->assertSame(PluginIntegrity::UNAVAILABLE, $result->status);
        $this->assertSame(0, $checker->commandsRun);
    }

    // ── Full check() with mocked HTTP ─────────────────────────────────────────
    // These tests use an anonymous subclass that overrides httpGetRaw() so no
    // real network calls are made.

    /**
     * When the API returns a matching sha256, status is VERIFIED and files are OK.
     */
    public function testCheckApiStatusVerifiedWhenAllFilesMatch(): void
    {
        $pluginDir = $this->createFakePlugin('all-ok');
        $mainSha   = hash_file('sha256', $pluginDir . '/all-ok.php');

        $checker = $this->makeCheckerWithMockResponse(json_encode([
            'files' => [
                'all-ok.php' => ['sha256' => $mainSha, 'md5' => 'x'],
            ],
        ]));

        $integrity = $checker->check($pluginDir);

        $this->assertFalse($integrity->isUnavailable());
        $this->assertSame(PluginIntegrity::VERIFIED, $integrity->status);
        $this->assertSame(1, $integrity->okCount);
        $this->assertEmpty($integrity->modifiedFiles);
        $this->assertEmpty($integrity->unexpectedFiles);
        $this->assertEmpty($integrity->missingFiles);
    }

    /**
     * When a local file hash differs from the official sha256, status is MODIFIED.
     */
    public function testCheckApiStatusModifiedWhenFileHashDiffers(): void
    {
        $pluginDir = $this->createFakePlugin('modified-test');

        $checker = $this->makeCheckerWithMockResponse(json_encode([
            'files' => [
                'modified-test.php' => ['sha256' => str_repeat('a', 64), 'md5' => 'x'],
            ],
        ]));

        $integrity = $checker->check($pluginDir);

        $this->assertFalse($integrity->isUnavailable());
        $this->assertSame(PluginIntegrity::MODIFIED, $integrity->status);
        $this->assertContains('modified-test.php', $integrity->modifiedFiles);
        $this->assertEmpty($integrity->unexpectedFiles);
        $this->assertEmpty($integrity->missingFiles);
    }

    /**
     * When an official file is absent from disk, it appears in missingFiles.
     * Status must be MODIFIED (not VERIFIED) even when no extra/modified files exist.
     */
    public function testCheckApiStatusModifiedWhenOnlyMissingFiles(): void
    {
        $pluginDir = $this->createFakePlugin('missing-only');
        $mainSha   = hash_file('sha256', $pluginDir . '/missing-only.php');

        $checker = $this->makeCheckerWithMockResponse(json_encode([
            'files' => [
                'missing-only.php' => ['sha256' => $mainSha, 'md5' => 'x'],
                'includes/gone.php' => ['sha256' => str_repeat('b', 64), 'md5' => 'x'],
            ],
        ]));

        $integrity = $checker->check($pluginDir);

        $this->assertFalse($integrity->isUnavailable());
        $this->assertSame(PluginIntegrity::MODIFIED, $integrity->status,
            'Plugin with missing official PHP files must have MODIFIED status, not VERIFIED');
        $this->assertContains('includes/gone.php', $integrity->missingFiles);
        $this->assertEmpty($integrity->unexpectedFiles);
        $this->assertEmpty($integrity->modifiedFiles);
        $this->assertSame(1, $integrity->okCount);
    }

    /**
     * A file that exists locally but is absent from the official manifest is EXTRA.
     */
    public function testCheckApiExtraFileDetected(): void
    {
        $pluginDir = $this->createFakePlugin('extra-test');
        $mainSha   = hash_file('sha256', $pluginDir . '/extra-test.php');

        // Plant an extra extensionless file
        mkdir($pluginDir . '/plugin-fw/templates', 0755, true);
        file_put_contents($pluginDir . '/plugin-fw/templates/c', "PK\x03\x04extra archive");

        $checker = $this->makeCheckerWithMockResponse(json_encode([
            'files' => [
                'extra-test.php' => ['sha256' => $mainSha, 'md5' => 'x'],
                // plugin-fw/templates/c is intentionally absent from official manifest
            ],
        ]));

        $integrity = $checker->check($pluginDir);

        $this->assertFalse($integrity->isUnavailable());
        $this->assertSame(PluginIntegrity::MODIFIED, $integrity->status);
        $this->assertContains('plugin-fw/templates/c', $integrity->unexpectedFiles,
            'Extensionless file not in official manifest must be EXTRA');
        $this->assertEmpty($integrity->modifiedFiles);
        $this->assertEmpty($integrity->missingFiles);
    }

    /**
     * Files in the official manifest that have ONLY md5 (no sha256) must not
     * cause false MODIFIED findings. They must also not appear as EXTRA or MISSING.
     * sha256 is the only hash algorithm WPMA uses for comparison.
     */
    public function testSha256OnlyNoMd5Fallback(): void
    {
        $pluginDir = $this->createFakePlugin('sha256-only');

        $checker = $this->makeCheckerWithMockResponse(json_encode([
            'files' => [
                'sha256-only.php' => ['md5' => 'some_old_md5_hash'],   // no sha256 key!
            ],
        ]));

        $integrity = $checker->check($pluginDir);

        $this->assertFalse($integrity->isUnavailable());
        $this->assertNotContains('sha256-only.php', $integrity->modifiedFiles,
            'md5-only manifest entry must not cause a false MODIFIED finding');
        $this->assertNotContains('sha256-only.php', $integrity->unexpectedFiles,
            'md5-only official file on disk must not appear as EXTRA');
        $this->assertNotContains('sha256-only.php', $integrity->missingFiles,
            'md5-only official file present on disk must not be MISSING');
    }

    // ── CHECKSUM_UNAVAILABLE vs UNAVAILABLE ───────────────────────────────────

    /**
     * A network error (status 0, no body) must produce CHECKSUM_UNAVAILABLE —
     * NOT UNAVAILABLE and NOT false EXTRA/MODIFIED findings.
     */
    public function testNetworkErrorReturnsChecksumUnavailable(): void
    {
        $pluginDir = $this->createFakePlugin('network-error-plugin');

        // Simulate total network failure (status 0, null body)
        $checker = $this->makeCheckerWithMockResponse(null, httpStatus: 0);

        $integrity = $checker->check($pluginDir);

        $this->assertSame(PluginIntegrity::CHECKSUM_UNAVAILABLE, $integrity->status,
            'Network error must yield CHECKSUM_UNAVAILABLE, not UNAVAILABLE');
        $this->assertTrue($integrity->isUnavailable(),
            'CHECKSUM_UNAVAILABLE must still be treated as unavailable (no false findings)');
        $this->assertEmpty($integrity->unexpectedFiles,
            'No false EXTRA findings when API is unreachable');
        $this->assertEmpty($integrity->modifiedFiles,
            'No false MODIFIED findings when API is unreachable');
    }

    /**
     * A 404 response means the plugin is not on WordPress.org.
     * Must return UNAVAILABLE (not CHECKSUM_UNAVAILABLE).
     */
    public function testApi404ReturnsUnavailableForPremiumPlugin(): void
    {
        $pluginDir = $this->createFakePlugin('premium-plugin');

        // Simulate 404 (plugin not found on WP.org)
        $checker = $this->makeCheckerWithMockResponse(null, httpStatus: 404);

        $integrity = $checker->check($pluginDir);

        $this->assertSame(PluginIntegrity::UNAVAILABLE, $integrity->status,
            '404 from checksum API must yield UNAVAILABLE (premium/custom plugin), not CHECKSUM_UNAVAILABLE');
        $this->assertTrue($integrity->isUnavailable());
        $this->assertEmpty($integrity->unexpectedFiles);
    }

    /**
     * A 500 server error must produce CHECKSUM_UNAVAILABLE, not UNAVAILABLE.
     */
    public function testServerErrorReturnsChecksumUnavailable(): void
    {
        $pluginDir = $this->createFakePlugin('server-error-plugin');

        $checker = $this->makeCheckerWithMockResponse(null, httpStatus: 500);

        $integrity = $checker->check($pluginDir);

        $this->assertSame(PluginIntegrity::CHECKSUM_UNAVAILABLE, $integrity->status,
            '5xx server error must yield CHECKSUM_UNAVAILABLE');
        $this->assertTrue($integrity->isUnavailable());
        $this->assertEmpty($integrity->unexpectedFiles);
    }

    // ── PluginIntegrityChecker API unavailable → CHECKSUM_UNAVAILABLE ─────────

    public function testNonExistentSlugReturnsUnavailable(): void
    {
        // 'wpma-nonexistent-slug-xyz-999' should 404 on WordPress.org
        $checker   = new PluginIntegrityChecker();
        $integrity = $checker->check($this->tmpDir);

        // Should return UNAVAILABLE (not MODIFIED, not throw)
        $this->assertTrue(
            $integrity->isUnavailable(),
            'Non-WordPress.org plugin should return UNAVAILABLE, not false-EXTRA findings'
        );
        $this->assertEmpty($integrity->unexpectedFiles, 'UNAVAILABLE must not produce false EXTRA findings');
        $this->assertEmpty($integrity->modifiedFiles,   'UNAVAILABLE must not produce false MODIFIED findings');
    }

    // ── PluginIntegrity debug summary ─────────────────────────────────────────

    public function testDebugSummaryFormat(): void
    {
        $integrity = new PluginIntegrity(
            status:          PluginIntegrity::MODIFIED,
            slug:            'yith-woocommerce-social-login',
            version:         '1.2.5',
            modifiedFiles:   [],
            unexpectedFiles: ['assets/css/ywsl_frontend.min.css', 'plugin-fw/templates/c'],
            missingFiles:    array_fill(0, 30, 'dummy.php'),
            method:          'api',
            officialCount:   501,
            localCount:      475,
            okCount:         471,
        );

        $summary = $integrity->debugSummary();

        $this->assertStringContainsString('yith-woocommerce-social-login', $summary);
        $this->assertStringContainsString('1.2.5', $summary);
        $this->assertStringContainsString('Official files: 501', $summary);
        $this->assertStringContainsString('Local files: 475', $summary);
        $this->assertStringContainsString('OK: 471', $summary);
        $this->assertStringContainsString('MISSING: 30', $summary);
        $this->assertStringContainsString('EXTRA: 2', $summary);
    }

    public function testDebugSummaryChecksumUnavailable(): void
    {
        $integrity = new PluginIntegrity(
            status:  PluginIntegrity::CHECKSUM_UNAVAILABLE,
            slug:    'some-plugin',
            version: '2.0.0',
        );

        $summary = $integrity->debugSummary();

        $this->assertStringContainsString('some-plugin', $summary);
        $this->assertStringContainsString('CHECKSUM_UNAVAILABLE', $summary);
        $this->assertStringNotContainsString('not on WordPress.org', $summary,
            'CHECKSUM_UNAVAILABLE must not say "not on WordPress.org"');
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Create a minimal fake plugin directory with a valid main PHP header file.
     *
     * @param string $slug Plugin slug (also used as directory name and main file basename)
     * @return string Absolute path to the plugin directory
     */
    private function createFakePlugin(string $slug): string
    {
        $pluginDir = $this->tmpDir . DIRECTORY_SEPARATOR . $slug;
        mkdir($pluginDir, 0755, true);
        file_put_contents(
            $pluginDir . DIRECTORY_SEPARATOR . $slug . '.php',
            "<?php\n/**\n * Plugin Name: {$slug}\n * Version: 1.0.0\n * Text Domain: {$slug}\n */\n",
        );
        return $pluginDir;
    }

    /**
     * Build a PluginIntegrityChecker subclass whose httpGetRaw() returns a
     * pre-defined response — no real network calls are made.
     *
     * @param string|null $body       Response body (null to simulate no body)
     * @param int         $httpStatus HTTP status code (0 = network error)
     */
    private function makeCheckerWithMockResponse(?string $body, int $httpStatus = 200): PluginIntegrityChecker
    {
        return new class($body, $httpStatus) extends PluginIntegrityChecker {
            public function __construct(
                private readonly ?string $mockBody,
                private readonly int     $mockStatus,
            ) {}

            protected function httpGetRaw(string $url): array
            {
                return [$this->mockStatus, $this->mockBody];
            }
        };
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST,
        );
        foreach ($it as $item) {
            $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
        }
        rmdir($dir);
    }
}
