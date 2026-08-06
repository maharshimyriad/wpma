<?php

declare(strict_types=1);

namespace Wpma\Tests\Models;

use PHPUnit\Framework\TestCase;
use Wpma\Models\Confidence;
use Wpma\Models\DetectionCategory;
use Wpma\Models\OutputFormat;
use Wpma\Models\Severity;
use Wpma\Models\WPContext;

/**
 * Tests for all backed enums defined in src/Models/Enums.php.
 */
final class EnumsTest extends TestCase
{
    // ──────────────────────────────────────────────────────────────── Severity

    public function testSeverityWeightOrdering(): void
    {
        $this->assertLessThan(
            Severity::LOW->weight(),
            Severity::INFORMATIONAL->weight(),
        );
        $this->assertLessThan(Severity::MEDIUM->weight(), Severity::LOW->weight());
        $this->assertLessThan(Severity::HIGH->weight(), Severity::MEDIUM->weight());
        $this->assertLessThan(Severity::CRITICAL->weight(), Severity::HIGH->weight());
    }

    public function testSeverityWeightRange(): void
    {
        foreach (Severity::cases() as $case) {
            $this->assertGreaterThanOrEqual(0, $case->weight());
            $this->assertLessThanOrEqual(4, $case->weight());
        }
    }

    public function testSeverityIsAtLeastReflexive(): void
    {
        foreach (Severity::cases() as $case) {
            $this->assertTrue($case->isAtLeast($case), "{$case->name} should be at least itself");
        }
    }

    /**
     * @dataProvider isAtLeastProvider
     */
    public function testSeverityIsAtLeast(Severity $a, Severity $b, bool $expected): void
    {
        $this->assertSame($expected, $a->isAtLeast($b));
    }

    public static function isAtLeastProvider(): array
    {
        return [
            'CRITICAL >= HIGH'          => [Severity::CRITICAL, Severity::HIGH, true],
            'CRITICAL >= INFORMATIONAL' => [Severity::CRITICAL, Severity::INFORMATIONAL, true],
            'LOW >= INFORMATIONAL'      => [Severity::LOW, Severity::INFORMATIONAL, true],
            'INFORMATIONAL >= LOW'      => [Severity::INFORMATIONAL, Severity::LOW, false],
            'LOW >= MEDIUM'             => [Severity::LOW, Severity::MEDIUM, false],
            'HIGH >= CRITICAL'          => [Severity::HIGH, Severity::CRITICAL, false],
        ];
    }

    public function testSeverityLabelIsUppercase(): void
    {
        foreach (Severity::cases() as $case) {
            $label = $case->label();
            $this->assertSame(strtoupper($label), $label, "label() should be uppercase for {$case->name}");
        }
    }

    public function testSeverityLabelMatchesName(): void
    {
        foreach (Severity::cases() as $case) {
            $this->assertSame($case->name, $case->label());
        }
    }

    public function testSeverityBackedValues(): void
    {
        $this->assertSame('informational', Severity::INFORMATIONAL->value);
        $this->assertSame('low',           Severity::LOW->value);
        $this->assertSame('medium',        Severity::MEDIUM->value);
        $this->assertSame('high',          Severity::HIGH->value);
        $this->assertSame('critical',      Severity::CRITICAL->value);
    }

    public function testSeverityFromValue(): void
    {
        $this->assertSame(Severity::HIGH, Severity::from('high'));
        $this->assertNull(Severity::tryFrom('unknown'));
    }

    // ──────────────────────────────────────────────────────────────── Confidence

    public function testConfidenceWeightOrdering(): void
    {
        $this->assertLessThan(Confidence::MEDIUM->weight(), Confidence::LOW->weight());
        $this->assertLessThan(Confidence::HIGH->weight(), Confidence::MEDIUM->weight());
    }

    public function testConfidenceWeightRange(): void
    {
        foreach (Confidence::cases() as $case) {
            $this->assertGreaterThanOrEqual(0, $case->weight());
            $this->assertLessThanOrEqual(2, $case->weight());
        }
    }

    public function testConfidenceBackedValues(): void
    {
        $this->assertSame('low',    Confidence::LOW->value);
        $this->assertSame('medium', Confidence::MEDIUM->value);
        $this->assertSame('high',   Confidence::HIGH->value);
    }

    // ──────────────────────────────────────────────────────────── DetectionCategory

    public function testDetectionCategoryHasExpectedCases(): void
    {
        $expected = [
            'OBFUSCATION', 'EXECUTION', 'NETWORK', 'PERSISTENCE',
            'USER_INPUT', 'FILE_MANIPULATION', 'SEO_SPAM', 'REDIRECT',
            'CREDENTIAL_STEAL', 'JS_INJECTION', 'WEBSHELL', 'BACKDOOR', 'CUSTOM',
            'INTEGRITY',
        ];

        $actual = array_map(fn ($c) => $c->name, DetectionCategory::cases());
        sort($expected);
        sort($actual);

        $this->assertSame($expected, $actual);
    }

    public function testDetectionCategoryBackedValues(): void
    {
        $this->assertSame('obfuscation',       DetectionCategory::OBFUSCATION->value);
        $this->assertSame('user_input',        DetectionCategory::USER_INPUT->value);
        $this->assertSame('file_manipulation', DetectionCategory::FILE_MANIPULATION->value);
        $this->assertSame('credential_steal',  DetectionCategory::CREDENTIAL_STEAL->value);
    }

    // ──────────────────────────────────────────────────────────────── OutputFormat

    public function testOutputFormatBackedValues(): void
    {
        $this->assertSame('text', OutputFormat::TEXT->value);
        $this->assertSame('json', OutputFormat::JSON->value);
        $this->assertSame('html', OutputFormat::HTML->value);
    }

    // ──────────────────────────────────────────────────────────────── WPContext

    public function testWPContextHighRiskCases(): void
    {
        $this->assertTrue(WPContext::UPLOAD->isHighRisk());
        $this->assertTrue(WPContext::MU_PLUGIN->isHighRisk());
    }

    public function testWPContextLowRiskCases(): void
    {
        $lowRisk = [
            WPContext::CORE,
            WPContext::PLUGIN,
            WPContext::THEME,
            WPContext::DROP_IN,
            WPContext::ARBITRARY,
        ];

        foreach ($lowRisk as $ctx) {
            $this->assertFalse($ctx->isHighRisk(), "{$ctx->name} should not be high risk");
        }
    }

    public function testWPContextBackedValues(): void
    {
        $this->assertSame('core',      WPContext::CORE->value);
        $this->assertSame('plugin',    WPContext::PLUGIN->value);
        $this->assertSame('theme',     WPContext::THEME->value);
        $this->assertSame('upload',    WPContext::UPLOAD->value);
        $this->assertSame('mu_plugin', WPContext::MU_PLUGIN->value);
        $this->assertSame('drop_in',   WPContext::DROP_IN->value);
        $this->assertSame('arbitrary', WPContext::ARBITRARY->value);
    }
}
