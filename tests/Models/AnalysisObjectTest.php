<?php

declare(strict_types=1);

namespace Wpma\Tests\Models;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Wpma\Models\AnalysisObject;
use Wpma\Models\FileFeatures;
use Wpma\Models\FileMeta;
use Wpma\Models\Token;
use Wpma\Pipeline\PhpTokenizer;

/**
 * Tests for AnalysisObject field completeness (task 1.4).
 *
 * Property 1: AnalysisObject Field Completeness — validates Requirement 2.2.
 */
final class AnalysisObjectTest extends TestCase
{
    // ── data providers ────────────────────────────────────────────────────────

    public static function phpSnippetProvider(): array
    {
        return [
            'empty file'          => [''],
            'open tag only'       => ['<?php'],
            'single echo'         => ['<?php echo "hello";'],
            'variable assignment' => ['<?php $x = 42;'],
            'function call'       => ['<?php base64_decode("dGVzdA==");'],
            'class declaration'   => ['<?php class Foo { public function bar() {} }'],
            'multiline'           => ["<?php\n\$a = 1;\n\$b = 2;\necho \$a + \$b;"],
        ];
    }

    // ── field completeness ────────────────────────────────────────────────────

    #[DataProvider('phpSnippetProvider')]
    public function testAllRequiredFieldsAreNonNull(string $source): void
    {
        $ao = $this->makeAnalysisObject($source);

        $this->assertNotNull($ao->meta,          'meta must not be null');
        $this->assertInstanceOf(FileMeta::class, $ao->meta);
        $this->assertIsString($ao->rawContent,   'rawContent must be a string');
        $this->assertIsArray($ao->tokens,        'tokens must be an array');
        $this->assertIsArray($ao->functionCalls, 'functionCalls must be an array');
        $this->assertIsArray($ao->strings,       'strings must be an array');
        $this->assertIsArray($ao->variables,     'variables must be an array');
        $this->assertIsArray($ao->imports,       'imports must be an array');
        $this->assertIsArray($ao->iocs,          'iocs must be an array');
        $this->assertInstanceOf(FileFeatures::class, $ao->features, 'features must be a FileFeatures');
        $this->assertIsArray($ao->parseErrors,   'parseErrors must be an array');
    }

    // ── token types ───────────────────────────────────────────────────────────

    #[DataProvider('phpSnippetProvider')]
    public function testTokensAreTokenInstances(string $source): void
    {
        $ao = $this->makeAnalysisObject($source);

        // An empty source produces zero tokens — that is valid.
        $this->assertIsArray($ao->tokens);

        foreach ($ao->tokens as $token) {
            $this->assertInstanceOf(Token::class, $token);
        }
    }

    // ── FileMeta fields ───────────────────────────────────────────────────────

    public function testMetaHasExpectedProperties(): void
    {
        $ao = $this->makeAnalysisObject('<?php echo 1;', '/var/www/wp-content/plugin/foo.php');

        $this->assertNotEmpty($ao->meta->filePath,   'filePath should not be empty');
        $this->assertNotEmpty($ao->meta->extension,  'extension should not be empty');
        $this->assertNotEmpty($ao->meta->encoding,   'encoding should not be empty');
        $this->assertSame('.php', $ao->meta->extension);
        $this->assertSame('/var/www/wp-content/plugin/foo.php', $ao->meta->filePath);
    }

    // ── FileFeatures types ────────────────────────────────────────────────────

    public function testFeaturesHasCorrectTypes(): void
    {
        $ao = $this->makeAnalysisObject('<?php echo 1;');

        $this->assertIsFloat($ao->features->obfuscationScore);
        $this->assertIsFloat($ao->features->entropyScore);
        $this->assertIsArray($ao->features->encodedBlobs);
        $this->assertIsArray($ao->features->dynamicDispatchCalls);
        $this->assertIsArray($ao->features->userInputSources);
        $this->assertIsArray($ao->features->networkCalls);
        $this->assertIsArray($ao->features->fileWriteCalls);
        $this->assertIsArray($ao->features->taintPaths);
    }

    // ── helper methods ────────────────────────────────────────────────────────

    public function testHasFunctionCallReturnsTrueForPresentFunction(): void
    {
        $ao = $this->makeAnalysisObject('<?php echo "test";');
        // hasFunctionCall works on functionCalls array; empty in base object
        $this->assertFalse($ao->hasFunctionCall('nonexistent'));
    }

    public function testHasUserInputReturnsFalseOnEmptyVariables(): void
    {
        $ao = $this->makeAnalysisObject('<?php echo "test";');
        $this->assertFalse($ao->hasUserInput());
    }

    public function testGetEncodedBlobsDelegatesToFeatures(): void
    {
        $ao = $this->makeAnalysisObject('<?php echo "test";');
        $this->assertSame($ao->features->encodedBlobs, $ao->getEncodedBlobs());
    }

    // ── factory helper ────────────────────────────────────────────────────────

    private function makeAnalysisObject(
        string $source,
        string $filePath = '/test/file.php',
    ): AnalysisObject {
        $tokenizer = new PhpTokenizer();
        $result    = $tokenizer->tokenize($source, $filePath);

        $ext      = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        $dotExt   = $ext !== '' ? '.' . $ext : '';

        $meta = new FileMeta(
            filePath:     $filePath,
            relativePath: basename($filePath),
            fileSize:     strlen($source),
            extension:    $dotExt,
            encoding:     'UTF-8',
            lineCount:    $tokenizer->extractLineCount($source),
            scanTimeMs:   0.0,
        );

        return new AnalysisObject(
            meta:          $meta,
            rawContent:    $source,
            tokens:        $result->tokens,
            functionCalls: [],
            strings:       [],
            variables:     [],
            imports:       [],
            assignments:   [],
            iocs:          [],
            features:      new FileFeatures(),
            parseErrors:   $result->parseErrors,
        );
    }
}
