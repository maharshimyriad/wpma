<?php

declare(strict_types=1);

namespace Wpma\Tests\Engine;

use PHPUnit\Framework\TestCase;
use Wpma\Config\ScanConfig;
use Wpma\Engine\FileDiscovery;
use Wpma\Models\ScanWarning;

/**
 * Tests for FileDiscovery.
 *
 * All tests use a temporary directory tree created and torn down per test.
 */
final class FileDiscoveryTest extends TestCase
{
    /** @var string Temporary directory root for this test run. */
    private string $tmpDir;

    protected function setUp(): void
    {
        parent::setUp();

        $this->tmpDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'wpma_test_' . uniqid('', true);
        mkdir($this->tmpDir, 0755, true);
    }

    protected function tearDown(): void
    {
        $this->removeDirRecursively($this->tmpDir);
        parent::tearDown();
    }

    // ─────────────────────────────────────────────── single-file mode ────────

    public function testSingleFileModeYieldsFile(): void
    {
        $file = $this->createFile('scan_me.php', '<?php echo 1;');

        $discovery = $this->makeDiscovery();
        $results   = iterator_to_array($discovery->discover($file));

        $this->assertCount(1, $results);
        $this->assertSame($file, $results[0]);
    }

    public function testSingleFileModeTooLargeEmitsWarning(): void
    {
        $file = $this->createFile('big.php', str_repeat('x', 100));

        // Limit is 10 bytes — file is 100 bytes.
        $discovery = $this->makeDiscovery(maxFileSizeBytes: 10);
        $results   = iterator_to_array($discovery->discover($file));

        $this->assertCount(0, $results);
        $this->assertCount(1, $discovery->warnings);
        $this->assertSame('skipped_size', $discovery->warnings[0]->warningType);
    }

    public function testSingleFileModeExcludedExtensionIsSkipped(): void
    {
        $file = $this->createFile('image.jpg', 'binary');

        $discovery = $this->makeDiscovery();
        $results   = iterator_to_array($discovery->discover($file));

        $this->assertCount(0, $results);
        // Excluded extensions are silently skipped — no warning expected.
        $this->assertCount(0, $discovery->warnings);
    }

    // ─────────────────────────────────────────────── directory mode ──────────

    public function testDirectoryModeYieldsPhpFiles(): void
    {
        $this->createFile('a.php', '<?php // a');
        $this->createFile('b.php', '<?php // b');
        $this->createFile('logo.png', 'binary');  // should be excluded

        $discovery = $this->makeDiscovery();
        $results   = iterator_to_array($discovery->discover($this->tmpDir));

        // Only .php files (png is excluded by default).
        $basenames = array_map('basename', $results);
        sort($basenames);
        $this->assertSame(['a.php', 'b.php'], $basenames);
    }

    public function testDirectoryModeRecursesIntoSubdirectories(): void
    {
        mkdir($this->tmpDir . DIRECTORY_SEPARATOR . 'sub', 0755, true);
        $this->createFile('top.php', '<?php // top');
        file_put_contents(
            $this->tmpDir . DIRECTORY_SEPARATOR . 'sub' . DIRECTORY_SEPARATOR . 'deep.php',
            '<?php // deep',
        );

        $discovery = $this->makeDiscovery();
        $results   = iterator_to_array($discovery->discover($this->tmpDir));

        $basenames = array_map('basename', $results);
        sort($basenames);
        $this->assertSame(['deep.php', 'top.php'], $basenames);
    }

    public function testDirectoryModeSkipsExcludedDirNames(): void
    {
        $nodeMod = $this->tmpDir . DIRECTORY_SEPARATOR . 'node_modules';
        mkdir($nodeMod, 0755, true);
        file_put_contents($nodeMod . DIRECTORY_SEPARATOR . 'should_skip.php', '<?php // skip');
        $this->createFile('include_me.php', '<?php // keep');

        $discovery = $this->makeDiscovery();
        $results   = iterator_to_array($discovery->discover($this->tmpDir));

        $basenames = array_map('basename', $results);
        $this->assertSame(['include_me.php'], $basenames);
        $this->assertNotContains('should_skip.php', $basenames);
    }

    public function testDirectoryModeSkipsExcludedDirNameInNestedPath(): void
    {
        $gitDir = $this->tmpDir . DIRECTORY_SEPARATOR . '.git';
        mkdir($gitDir, 0755, true);
        file_put_contents($gitDir . DIRECTORY_SEPARATOR . 'config', 'git config');
        $this->createFile('real.php', '<?php // real');

        $discovery = $this->makeDiscovery();
        $results   = iterator_to_array($discovery->discover($this->tmpDir));

        $basenames = array_map('basename', $results);
        $this->assertNotContains('config', $basenames);
        $this->assertContains('real.php', $basenames);
    }

    public function testDirectoryModeSkipsOversizedFilesAndEmitsWarning(): void
    {
        $this->createFile('small.php', '<?php');              // ~5 bytes
        $this->createFile('huge.php', str_repeat('x', 200)); // 200 bytes

        // Allow up to 50 bytes.
        $discovery = $this->makeDiscovery(maxFileSizeBytes: 50);
        $results   = iterator_to_array($discovery->discover($this->tmpDir));

        $basenames = array_map('basename', $results);
        $this->assertContains('small.php', $basenames);
        $this->assertNotContains('huge.php', $basenames);

        $sizeWarnings = array_filter(
            $discovery->warnings,
            fn(ScanWarning $w) => $w->warningType === 'skipped_size',
        );
        $this->assertCount(1, $sizeWarnings);
        $this->assertStringContainsString('huge.php', array_values($sizeWarnings)[0]->filePath);
    }

    public function testDirectoryModeSkipsExcludedExtensions(): void
    {
        $this->createFile('page.php', '<?php');
        $this->createFile('photo.jpg', 'binary');
        $this->createFile('font.woff2', 'binary');

        $discovery = $this->makeDiscovery();
        $results   = iterator_to_array($discovery->discover($this->tmpDir));

        $basenames = array_map('basename', $results);
        $this->assertContains('page.php', $basenames);
        $this->assertNotContains('photo.jpg', $basenames);
        $this->assertNotContains('font.woff2', $basenames);
    }

    // ───────────────────────────────────────── custom excludeDirs config ──────

    public function testCustomExcludeDirsAreRespected(): void
    {
        $uploadDir = $this->tmpDir . DIRECTORY_SEPARATOR . 'cache';
        mkdir($uploadDir, 0755, true);
        file_put_contents($uploadDir . DIRECTORY_SEPARATOR . 'junk.php', '<?php');
        $this->createFile('real.php', '<?php // real');

        $discovery = $this->makeDiscovery(excludeDirs: ['cache']);
        $results   = iterator_to_array($discovery->discover($this->tmpDir));

        $basenames = array_map('basename', $results);
        $this->assertContains('real.php', $basenames);
        $this->assertNotContains('junk.php', $basenames);
    }

    // ───────────────────────────────────────── warnings collection ───────────

    public function testWarningsAreResetBetweenDiscoverCalls(): void
    {
        $file = $this->createFile('big.php', str_repeat('x', 100));

        $discovery = $this->makeDiscovery(maxFileSizeBytes: 10);

        // First call produces 1 warning.
        iterator_to_array($discovery->discover($file));
        $this->assertCount(1, $discovery->warnings);

        // Second call should reset warnings.
        iterator_to_array($discovery->discover($file));
        $this->assertCount(1, $discovery->warnings);

        // Now scan a valid file — should yield 0 warnings.
        $small = $this->createFile('small.php', '<?php');
        iterator_to_array($discovery->discover($small));
        $this->assertCount(0, $discovery->warnings);
    }

    public function testWarningsAreNotYieldedFromDiscover(): void
    {
        // Oversized file — skipped with a warning.
        $file = $this->createFile('big.php', str_repeat('x', 100));

        $discovery = $this->makeDiscovery(maxFileSizeBytes: 10);
        $results   = iterator_to_array($discovery->discover($file));

        // Nothing yielded.
        $this->assertCount(0, $results);
        // Warning recorded on the object instead.
        $this->assertCount(1, $discovery->warnings);
        $this->assertInstanceOf(ScanWarning::class, $discovery->warnings[0]);
    }

    // ──────────────────────────────────────── warning types are correct ───────

    public function testSkippedSizeWarningType(): void
    {
        $file = $this->createFile('big.php', str_repeat('a', 50));

        $discovery = $this->makeDiscovery(maxFileSizeBytes: 5);
        iterator_to_array($discovery->discover($file));

        $this->assertSame('skipped_size', $discovery->warnings[0]->warningType);
    }

    // ──────────────────────────────────────── non-existent path ─────────────

    public function testNonExistentPathEmitsWarning(): void
    {
        $discovery = $this->makeDiscovery();
        $results   = iterator_to_array($discovery->discover('/this/does/not/exist/at/all'));

        $this->assertCount(0, $results);
        $this->assertCount(1, $discovery->warnings);
        $this->assertSame('skipped_permission', $discovery->warnings[0]->warningType);
    }

    // ─────────────────────────────────────────────────── helpers ─────────────

    /**
     * Build a ScanConfig with sensible defaults for testing.
     *
     * @param int      $maxFileSizeBytes
     * @param string[] $excludeDirs
     * @param string[] $excludeExtensions
     */
    private function makeDiscovery(
        int   $maxFileSizeBytes  = 10_485_760,
        array $excludeDirs       = ['.git', 'node_modules', '.svn'],
        array $excludeExtensions = [
            '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg',
            '.woff', '.woff2', '.ttf', '.eot',
            '.mp4', '.mp3',
            '.zip', '.tar', '.gz',
        ],
    ): FileDiscovery {
        $config = new ScanConfig(
            target:            $this->tmpDir,
            maxFileSizeBytes:  $maxFileSizeBytes,
            excludeDirs:       $excludeDirs,
            excludeExtensions: $excludeExtensions,
        );

        return new FileDiscovery($config);
    }

    /**
     * Create a file inside $this->tmpDir and return its full path.
     */
    private function createFile(string $name, string $contents): string
    {
        $path = $this->tmpDir . DIRECTORY_SEPARATOR . $name;
        file_put_contents($path, $contents);
        return $path;
    }

    /**
     * Recursively remove a directory tree.
     */
    private function removeDirRecursively(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $items = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST,
        );

        foreach ($items as $item) {
            if ($item->isDir()) {
                rmdir($item->getPathname());
            } else {
                unlink($item->getPathname());
            }
        }

        rmdir($dir);
    }
}
