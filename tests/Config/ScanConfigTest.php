<?php

declare(strict_types=1);

namespace Wpma\Tests\Config;

use PHPUnit\Framework\TestCase;
use Wpma\Cli\ScanTargetType;
use Wpma\Config\ScanConfig;
use Wpma\Models\OutputFormat;
use Wpma\Models\Severity;

/**
 * Tests for ScanConfig — defaults, readonly behaviour, and fromCliOptions().
 */
final class ScanConfigTest extends TestCase
{
    // ───────────────────────────────────────────────────── constructor defaults

    public function testDefaultOutputFormatIsText(): void
    {
        $config = new ScanConfig('/var/www');
        $this->assertSame(OutputFormat::TEXT, $config->outputFormat);
    }

    public function testDefaultMinSeverityIsInformational(): void
    {
        $config = new ScanConfig('/var/www');
        $this->assertSame(Severity::INFORMATIONAL, $config->minSeverity);
    }

    public function testDefaultWorkers(): void
    {
        $config = new ScanConfig('/var/www');
        $this->assertSame(4, $config->workers);
    }

    public function testDefaultMaxFileSizeIsTenMB(): void
    {
        $config = new ScanConfig('/var/www');
        $this->assertSame(10_485_760, $config->maxFileSizeBytes);
    }

    public function testDefaultNoColorIsFalse(): void
    {
        $config = new ScanConfig('/var/www');
        $this->assertFalse($config->noColor);
    }

    public function testDefaultShowProgressIsFalse(): void
    {
        $config = new ScanConfig('/var/www');
        $this->assertFalse($config->showProgress);
    }

    public function testDefaultOutputFileIsNull(): void
    {
        $config = new ScanConfig('/var/www');
        $this->assertNull($config->outputFile);
    }

    public function testDefaultRulesDirIsNull(): void
    {
        $config = new ScanConfig('/var/www');
        $this->assertNull($config->rulesDir);
    }

    public function testDefaultTargetTypeIsUnknown(): void
    {
        $config = new ScanConfig('/var/www');
        $this->assertSame(ScanTargetType::UNKNOWN, $config->targetType);
    }

    public function testDefaultExcludeDirs(): void
    {
        $config = new ScanConfig('/var/www');
        $this->assertContains('.git', $config->excludeDirs);
        $this->assertContains('node_modules', $config->excludeDirs);
        $this->assertContains('.svn', $config->excludeDirs);
    }

    public function testDefaultExcludeExtensionsContainsBinaryFormats(): void
    {
        $config = new ScanConfig('/var/www');
        foreach (['.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg', '.woff', '.woff2',
                  '.ttf', '.eot', '.mp4', '.mp3', '.zip', '.tar', '.gz'] as $ext) {
            $this->assertContains($ext, $config->excludeExtensions, "Missing extension: {$ext}");
        }
    }

    // ─────────────────────────────────────────────────────── target is stored

    public function testTargetIsStored(): void
    {
        $config = new ScanConfig('/some/path');
        $this->assertSame('/some/path', $config->target);
    }

    // ─────────────────────────────────────────────────────────────── readonly

    public function testPropertiesAreReadonly(): void
    {
        $config = new ScanConfig('/var/www');

        $this->expectException(\Error::class);

        // Attempt to mutate a readonly property — must throw.
        /** @phpstan-ignore-line */
        $config->workers = 99;
    }

    // ─────────────────────────────────────────────────────── fromCliOptions()

    public function testFromCliOptionsMinimalOptions(): void
    {
        $config = ScanConfig::fromCliOptions('/path/to/wp', []);

        $this->assertSame('/path/to/wp', $config->target);
        $this->assertSame(OutputFormat::TEXT, $config->outputFormat);
        $this->assertSame(Severity::INFORMATIONAL, $config->minSeverity);
        $this->assertFalse($config->noColor);
        $this->assertSame(4, $config->workers);
        $this->assertSame(10_485_760, $config->maxFileSizeBytes);
        $this->assertFalse($config->showProgress);
        $this->assertNull($config->outputFile);
        $this->assertNull($config->rulesDir);
        $this->assertSame(ScanTargetType::UNKNOWN, $config->targetType);
    }

    public function testFromCliOptionsOutputJson(): void
    {
        $config = ScanConfig::fromCliOptions('/wp', ['output' => 'json']);
        $this->assertSame(OutputFormat::JSON, $config->outputFormat);
    }

    public function testFromCliOptionsOutputHtml(): void
    {
        $config = ScanConfig::fromCliOptions('/wp', ['output' => 'html']);
        $this->assertSame(OutputFormat::HTML, $config->outputFormat);
    }

    public function testFromCliOptionsUnknownOutputFallsBackToText(): void
    {
        $config = ScanConfig::fromCliOptions('/wp', ['output' => 'xml']);
        $this->assertSame(OutputFormat::TEXT, $config->outputFormat);
    }

    public function testFromCliOptionsSeverityHigh(): void
    {
        $config = ScanConfig::fromCliOptions('/wp', ['severity' => 'high']);
        $this->assertSame(Severity::HIGH, $config->minSeverity);
    }

    public function testFromCliOptionsUnknownSeverityFallsBackToInformational(): void
    {
        $config = ScanConfig::fromCliOptions('/wp', ['severity' => 'extreme']);
        $this->assertSame(Severity::INFORMATIONAL, $config->minSeverity);
    }

    public function testFromCliOptionsNoColor(): void
    {
        $config = ScanConfig::fromCliOptions('/wp', ['no-color' => true]);
        $this->assertTrue($config->noColor);
    }

    public function testFromCliOptionsWorkers(): void
    {
        $config = ScanConfig::fromCliOptions('/wp', ['workers' => 8]);
        $this->assertSame(8, $config->workers);
    }

    public function testFromCliOptionsMaxFileSize(): void
    {
        $config = ScanConfig::fromCliOptions('/wp', ['max-file-size' => 5_242_880]);
        $this->assertSame(5_242_880, $config->maxFileSizeBytes);
    }

    public function testFromCliOptionsProgress(): void
    {
        $config = ScanConfig::fromCliOptions('/wp', ['progress' => true]);
        $this->assertTrue($config->showProgress);
    }

    public function testFromCliOptionsOutputFile(): void
    {
        $config = ScanConfig::fromCliOptions('/wp', ['output-file' => '/tmp/report.json']);
        $this->assertSame('/tmp/report.json', $config->outputFile);
    }

    public function testFromCliOptionsRulesDir(): void
    {
        $config = ScanConfig::fromCliOptions('/wp', ['rules-dir' => '/custom/rules']);
        $this->assertSame('/custom/rules', $config->rulesDir);
    }

    public function testFromCliOptionsTargetType(): void
    {
        $config = ScanConfig::fromCliOptions('/wp', ['target-type' => 'SINGLE_PLUGIN']);
        $this->assertSame(ScanTargetType::SINGLE_PLUGIN, $config->targetType);
    }

    /**
     * @dataProvider allSeverityValuesProvider
     */
    public function testFromCliOptionsAllSeverityValues(string $value, Severity $expected): void
    {
        $config = ScanConfig::fromCliOptions('/wp', ['severity' => $value]);
        $this->assertSame($expected, $config->minSeverity);
    }

    public static function allSeverityValuesProvider(): array
    {
        return [
            ['informational', Severity::INFORMATIONAL],
            ['low',           Severity::LOW],
            ['medium',        Severity::MEDIUM],
            ['high',          Severity::HIGH],
            ['critical',      Severity::CRITICAL],
        ];
    }

    /**
     * @dataProvider allOutputFormatValuesProvider
     */
    public function testFromCliOptionsAllOutputFormats(string $value, OutputFormat $expected): void
    {
        $config = ScanConfig::fromCliOptions('/wp', ['output' => $value]);
        $this->assertSame($expected, $config->outputFormat);
    }

    public static function allOutputFormatValuesProvider(): array
    {
        return [
            ['text', OutputFormat::TEXT],
            ['json', OutputFormat::JSON],
            ['html', OutputFormat::HTML],
        ];
    }
}
