<?php

declare(strict_types=1);

namespace Wpma\Tests\WP;

use PHPUnit\Framework\TestCase;
use Wpma\WP\PluginIntegrity;
use Wpma\WP\WpCoreIntegrityChecker;

final class WpCoreIntegrityCheckerTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tmpDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'wpma-core-' . bin2hex(random_bytes(6));
        mkdir($this->tmpDir, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeDirectory($this->tmpDir);
        parent::tearDown();
    }

    public function testVerifiedCoreFilesAreExposedInIntegrityResult(): void
    {
        $siteRoot = $this->createWordPressSite([
            'wp-includes/version.php' => "<?php\n\$wp_version = '7.0';\n",
            'wp-includes/functions.php' => "<?php echo 'functions';\n",
            'wp-admin/includes/class-wp-filesystem-direct.php' => "<?php echo 'fs';\n",
        ]);

        $checksums = [
            'wp-includes/version.php' => md5_file($siteRoot . '/wp-includes/version.php'),
            'wp-includes/functions.php' => md5_file($siteRoot . '/wp-includes/functions.php'),
            'wp-admin/includes/class-wp-filesystem-direct.php' => md5_file($siteRoot . '/wp-admin/includes/class-wp-filesystem-direct.php'),
        ];

        $checker = new class(json_encode(['checksums' => $checksums])) extends WpCoreIntegrityChecker {
            public function __construct(private readonly string $body) {}

            protected function httpGetRaw(string $url): array
            {
                return [200, $this->body];
            }
        };

        $integrity = $checker->check($siteRoot);

        $this->assertSame(PluginIntegrity::VERIFIED, $integrity->status);
        $this->assertSame(3, $integrity->okCount);
        $this->assertEqualsCanonicalizing([
            'wp-includes/version.php',
            'wp-includes/functions.php',
            'wp-admin/includes/class-wp-filesystem-direct.php',
        ], $integrity->verifiedFiles);
    }

    private function createWordPressSite(array $files): string
    {
        $siteRoot = $this->tmpDir . DIRECTORY_SEPARATOR . 'site';
        mkdir($siteRoot . DIRECTORY_SEPARATOR . 'wp-admin', 0777, true);
        mkdir($siteRoot . DIRECTORY_SEPARATOR . 'wp-includes', 0777, true);
        mkdir($siteRoot . DIRECTORY_SEPARATOR . 'wp-content', 0777, true);
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
