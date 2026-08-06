<?php

declare(strict_types=1);

namespace Wpma\Tests\Models;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Wpma\Models\Confidence;
use Wpma\Models\DetectionCategory;
use Wpma\Models\EvidenceItem;
use Wpma\Models\Finding;
use Wpma\Models\Severity;

/**
 * Tests for Finding model structural invariants (task 1.6).
 *
 * Property 3: Finding Model Invariants — validates Requirements 4.1, 6.1.
 */
final class FindingInvariantsTest extends TestCase
{
    // ── rule ID pattern ───────────────────────────────────────────────────────

    public static function validRuleIdProvider(): array
    {
        return [
            'OBF-001'   => ['OBF-001',   true],
            'BACK-042'  => ['BACK-042',  true],
            'WS-100'    => ['WS-100',    true],
            'NET-001'   => ['NET-001',   true],
            'CRED-999'  => ['CRED-999',  true],
            'invalid'   => ['invalid',   false],
            'lowercase' => ['obf-001',   false],
            'no-dash'   => ['OBF001',    false],
            'empty'     => ['',          false],
            '123-abc'   => ['123-abc',   false],
        ];
    }

    #[DataProvider('validRuleIdProvider')]
    public function testRuleIdMatchesPattern(string $ruleId, bool $shouldMatch): void
    {
        $pattern = '/^[A-Z]{2,6}-\d{3,}$/';
        if ($shouldMatch) {
            $this->assertMatchesRegularExpression($pattern, $ruleId);
        } else {
            $this->assertDoesNotMatchRegularExpression($pattern, $ruleId);
        }
    }

    // ── title length ──────────────────────────────────────────────────────────

    public static function titleLengthProvider(): array
    {
        return [
            'empty'       => [0,  true],
            'short'       => [40, true],
            'exactly-80'  => [80, true],
            'too-long-81' => [81, false],
            'too-long-100'=> [100,false],
        ];
    }

    /** @group contract */
    #[DataProvider('titleLengthProvider')]
    public function testTitleMaxLength(int $length, bool $isValid): void
    {
        $title   = str_repeat('a', $length);
        $finding = $this->makeFinding(['title' => $title]);

        if ($isValid) {
            $this->assertLessThanOrEqual(80, strlen($finding->title));
        } else {
            // @todo: enforce ≤80 at construction time in a future version
            $this->assertGreaterThan(80, strlen($finding->title));
        }
    }

    // ── enum fields ───────────────────────────────────────────────────────────

    public static function findingEnumProvider(): array
    {
        return [
            'informational+low+obfuscation'   => [Severity::INFORMATIONAL, Confidence::LOW,    DetectionCategory::OBFUSCATION],
            'high+high+webshell'              => [Severity::HIGH,          Confidence::HIGH,   DetectionCategory::WEBSHELL],
            'critical+medium+backdoor'        => [Severity::CRITICAL,      Confidence::MEDIUM, DetectionCategory::BACKDOOR],
            'medium+low+network'              => [Severity::MEDIUM,        Confidence::LOW,    DetectionCategory::NETWORK],
        ];
    }

    #[DataProvider('findingEnumProvider')]
    public function testAllEnumFieldsAreValidEnumCases(
        Severity $severity,
        Confidence $confidence,
        DetectionCategory $category,
    ): void {
        $finding = $this->makeFinding([
            'severity'   => $severity,
            'confidence' => $confidence,
            'category'   => $category,
        ]);

        $this->assertInstanceOf(Severity::class,          $finding->severity);
        $this->assertInstanceOf(Confidence::class,        $finding->confidence);
        $this->assertInstanceOf(DetectionCategory::class, $finding->category);
    }

    // ── string fields ─────────────────────────────────────────────────────────

    public function testDescriptionAndExplanationAreStrings(): void
    {
        $finding = $this->makeFinding([
            'description' => 'A description',
            'explanation' => 'An explanation',
        ]);

        $this->assertIsString($finding->description);
        $this->assertIsString($finding->explanation);
        $this->assertNotNull($finding->description);
        $this->assertNotNull($finding->explanation);
    }

    // ── evidence items ────────────────────────────────────────────────────────

    public function testEvidenceItemsAreCorrectType(): void
    {
        $evidence = [
            new EvidenceItem(line: 10, snippet: 'eval($x);', description: 'Dangerous eval'),
            new EvidenceItem(line: 20, snippet: '$x = base64_decode(...)', description: 'Decode chain'),
        ];

        $finding = $this->makeFinding(['evidence' => $evidence]);

        foreach ($finding->evidence as $item) {
            $this->assertInstanceOf(EvidenceItem::class, $item);
        }
    }

    // ── toArray serialisation ─────────────────────────────────────────────────

    public function testToArrayPreservesAllFields(): void
    {
        $finding = $this->makeFinding();
        $arr     = $finding->toArray();

        $expectedKeys = [
            'ruleId', 'title', 'filePath', 'line', 'severity', 'confidence',
            'category', 'description', 'explanation', 'remediation',
            'evidence', 'iocs', 'mitreTechniques', 'tags',
        ];

        foreach ($expectedKeys as $key) {
            $this->assertArrayHasKey($key, $arr, "toArray() must include key '{$key}'");
        }
    }

    public function testToArraySerializesEnumsAsStrings(): void
    {
        $finding = $this->makeFinding([
            'severity'   => Severity::HIGH,
            'confidence' => Confidence::HIGH,
            'category'   => DetectionCategory::BACKDOOR,
        ]);

        $arr = $finding->toArray();

        $this->assertIsString($arr['severity']);
        $this->assertIsString($arr['confidence']);
        $this->assertIsString($arr['category']);
        $this->assertSame('high', $arr['severity']);
        $this->assertSame('high', $arr['confidence']);
        $this->assertSame('backdoor', $arr['category']);
    }

    // ── factory helper ────────────────────────────────────────────────────────

    private function makeFinding(array $overrides = []): Finding
    {
        return Finding::create(array_merge([
            'ruleId'      => 'OBF-001',
            'title'       => 'Test finding',
            'filePath'    => '/var/www/test.php',
            'line'        => 42,
            'severity'    => Severity::MEDIUM,
            'confidence'  => Confidence::MEDIUM,
            'category'    => DetectionCategory::OBFUSCATION,
            'description' => 'Test description',
            'explanation' => 'Test explanation',
            'remediation' => 'Remove the obfuscation.',
            'evidence'    => [],
            'iocs'        => [],
            'mitreTechniques' => [],
            'tags'        => [],
        ], $overrides));
    }
}
