<?php

declare(strict_types=1);

namespace Wpma\Tests\Cli;

use PHPUnit\Framework\TestCase;
use Wpma\Cli\ScanTargetResolver;
use Wpma\Cli\ScanTargetType;

final class ScanTargetResolverTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tmpDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'wpma-targets-' . bin2hex(random_bytes(6));
        mkdir($this->tmpDir, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeDirectory($this->tmpDir);
        parent::tearDown();
    }

    public function testDetectsWordPressSite(): void
    {
        $site = $this->createWordPressSite('site');

        $detected = ScanTargetResolver::resolve($site);

        $this->assertSame(ScanTargetType::WORDPRESS_SITE, $detected->targetType);
        $this->assertSame('Full Site', $detected->scanMode);
        $this->assertSame(realpath($site), $detected->resolvedPath);
    }

    public function testDetectsWordPressCore(): void
    {
        $core = $this->tmpDir . DIRECTORY_SEPARATOR . 'wordpress-core';
        mkdir($core . DIRECTORY_SEPARATOR . 'wp-admin', 0777, true);
        mkdir($core . DIRECTORY_SEPARATOR . 'wp-includes', 0777, true);

        $detected = ScanTargetResolver::resolve($core);

        $this->assertSame(ScanTargetType::WORDPRESS_CORE, $detected->targetType);
        $this->assertSame('Core', $detected->scanMode);
    }

    public function testDetectsPluginsDirectory(): void
    {
        $site = $this->createWordPressSite('plugins-site');
        $pluginsDir = $site . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'plugins';

        $detected = ScanTargetResolver::resolve($pluginsDir);

        $this->assertSame(ScanTargetType::PLUGINS_DIRECTORY, $detected->targetType);
        $this->assertSame('Plugins', $detected->scanMode);
    }

    public function testDetectsSinglePlugin(): void
    {
        $site = $this->createWordPressSite('single-plugin-site');
        $pluginDir = $site . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'plugins' . DIRECTORY_SEPARATOR . 'wordfence';
        mkdir($pluginDir, 0777, true);

        $detected = ScanTargetResolver::resolve($pluginDir);

        $this->assertSame(ScanTargetType::SINGLE_PLUGIN, $detected->targetType);
        $this->assertSame('Plugin', $detected->scanMode);
        $this->assertSame('wordfence', $detected->componentName);
    }

    public function testDetectsThemesDirectory(): void
    {
        $site = $this->createWordPressSite('themes-site');
        $themesDir = $site . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'themes';

        $detected = ScanTargetResolver::resolve($themesDir);

        $this->assertSame(ScanTargetType::THEMES_DIRECTORY, $detected->targetType);
        $this->assertSame('Themes', $detected->scanMode);
    }

    public function testDetectsSingleTheme(): void
    {
        $site = $this->createWordPressSite('single-theme-site');
        $themeDir = $site . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'themes' . DIRECTORY_SEPARATOR . 'astra';
        mkdir($themeDir, 0777, true);

        $detected = ScanTargetResolver::resolve($themeDir);

        $this->assertSame(ScanTargetType::SINGLE_THEME, $detected->targetType);
        $this->assertSame('Theme', $detected->scanMode);
        $this->assertSame('astra', $detected->componentName);
    }

    public function testDetectsUploadsDirectory(): void
    {
        $site = $this->createWordPressSite('uploads-site');
        $uploadsDir = $site . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . '2026' . DIRECTORY_SEPARATOR . '08';
        mkdir($uploadsDir, 0777, true);

        $detected = ScanTargetResolver::resolve($uploadsDir);

        $this->assertSame(ScanTargetType::UPLOADS_DIRECTORY, $detected->targetType);
        $this->assertSame('Uploads', $detected->scanMode);
    }

    public function testDetectsSingleFile(): void
    {
        $file = $this->tmpDir . DIRECTORY_SEPARATOR . 'suspicious.php';
        file_put_contents($file, "<?php echo 'test';");

        $detected = ScanTargetResolver::resolve($file);

        $this->assertSame(ScanTargetType::SINGLE_FILE, $detected->targetType);
        $this->assertSame('Single File', $detected->scanMode);
    }

    public function testDetectsGenericDirectory(): void
    {
        $dir = $this->tmpDir . DIRECTORY_SEPARATOR . 'generic';
        mkdir($dir, 0777, true);

        $detected = ScanTargetResolver::resolve($dir);

        $this->assertSame(ScanTargetType::GENERIC_DIRECTORY, $detected->targetType);
        $this->assertSame('Directory', $detected->scanMode);
    }

    public function testDetectsUnknownForMissingTarget(): void
    {
        $missing = $this->tmpDir . DIRECTORY_SEPARATOR . 'missing';

        $detected = ScanTargetResolver::resolve($missing);

        $this->assertSame(ScanTargetType::UNKNOWN, $detected->targetType);
        $this->assertSame('Unknown', $detected->scanMode);
        $this->assertSame(sprintf('Target does not exist: %s', $missing), $detected->validationError);
        $this->assertFalse($detected->isValid());
    }

    public function testPluginsOverrideResolvesFromSiteRoot(): void
    {
        $site = $this->createWordPressSite('override-site');

        $detected = ScanTargetResolver::resolve($site, ['plugins' => true]);

        $this->assertTrue($detected->usedExplicitOverride);
        $this->assertSame(ScanTargetType::PLUGINS_DIRECTORY, $detected->targetType);
        $this->assertSame(
            realpath($site . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'plugins'),
            $detected->resolvedPath
        );
    }

    public function testPluginsOverrideReturnsHelpfulValidationMessage(): void
    {
        $dir = $this->tmpDir . DIRECTORY_SEPARATOR . 'random';
        mkdir($dir, 0777, true);

        $detected = ScanTargetResolver::resolve($dir, ['plugins' => true]);

        $this->assertSame(ScanTargetType::UNKNOWN, $detected->targetType);
        $this->assertSame(
            sprintf('wp-content/plugins could not be found for --plugins: %s', realpath($dir)),
            $detected->validationError
        );
    }

    private function createWordPressSite(string $name): string
    {
        $site = $this->tmpDir . DIRECTORY_SEPARATOR . $name;
        mkdir($site . DIRECTORY_SEPARATOR . 'wp-admin', 0777, true);
        mkdir($site . DIRECTORY_SEPARATOR . 'wp-includes', 0777, true);
        mkdir($site . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'plugins', 0777, true);
        mkdir($site . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'themes', 0777, true);
        file_put_contents($site . DIRECTORY_SEPARATOR . 'wp-config.php', "<?php\n");

        return $site;
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
