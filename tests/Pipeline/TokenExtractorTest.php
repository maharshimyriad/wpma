<?php

declare(strict_types=1);

namespace Wpma\Tests\Pipeline;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Wpma\Models\ExtractedString;
use Wpma\Models\FunctionCall;
use Wpma\Models\IncludeStatement;
use Wpma\Models\VariableRef;
use Wpma\Pipeline\PhpTokenizer;
use Wpma\Pipeline\TokenExtractor;
use Wpma\Pipeline\TokenExtractorResult;

/**
 * Unit tests for TokenExtractor::extract().
 *
 * Every test tokenizes a PHP snippet via PhpTokenizer and then passes the
 * resulting token array through TokenExtractor, which mirrors production usage.
 */
class TokenExtractorTest extends TestCase
{
    private PhpTokenizer $tokenizer;
    private TokenExtractor $extractor;

    protected function setUp(): void
    {
        $this->tokenizer = new PhpTokenizer();
        $this->extractor = new TokenExtractor();
    }

    // ── return type ───────────────────────────────────────────────────────────

    public function testExtractReturnsTokenExtractorResult(): void
    {
        $tokens = $this->tokenize('<?php echo "hello";');

        $result = $this->extractor->extract($tokens);

        $this->assertInstanceOf(TokenExtractorResult::class, $result);
    }

    public function testResultHasArrayFields(): void
    {
        $tokens = $this->tokenize('<?php $x = 1;');

        $result = $this->extractor->extract($tokens);

        $this->assertIsArray($result->functionCalls);
        $this->assertIsArray($result->strings);
        $this->assertIsArray($result->variables);
        $this->assertIsArray($result->imports);
    }

    public function testEmptySourceYieldsEmptyCollections(): void
    {
        $tokens = $this->tokenize('<?php ');

        $result = $this->extractor->extract($tokens);

        $this->assertSame([], $result->functionCalls);
        $this->assertSame([], $result->strings);
        $this->assertSame([], $result->variables);
        $this->assertSame([], $result->imports);
    }

    // ── function calls ────────────────────────────────────────────────────────

    public function testSimpleFunctionCallDetected(): void
    {
        $tokens = $this->tokenize('<?php base64_decode("abc");');

        $result = $this->extractor->extract($tokens);

        $this->assertCount(1, $result->functionCalls);
        $call = $result->functionCalls[0];
        $this->assertInstanceOf(FunctionCall::class, $call);
        $this->assertSame('base64_decode', $call->name);
        $this->assertFalse($call->isDynamic);
    }

    public function testFunctionCallArgumentsCaptured(): void
    {
        $tokens = $this->tokenize('<?php str_replace("a", "b", $str);');

        $result = $this->extractor->extract($tokens);

        // str_replace call should be detected
        $calls = array_filter(
            $result->functionCalls,
            static fn(FunctionCall $c) => $c->name === 'str_replace',
        );
        $this->assertCount(1, $calls);

        $call = array_values($calls)[0];
        $this->assertCount(3, $call->args);
    }

    public function testCollectArgsHandlesSimpleArguments(): void
    {
        $call = $this->extractSingleFunctionCall('<?php foo($a, $b);');

        $this->assertSame('foo', $call->name);
        $this->assertCount(2, $call->args);
        $this->assertSame('$a', $call->args[0]);
        $this->assertSame('$b', $call->args[1]);
    }

    public function testCollectArgsHandlesNestedFunctionCallArguments(): void
    {
        $call = $this->extractSingleFunctionCall('<?php foo(bar($a, $b), $c);');

        $this->assertSame('foo', $call->name);
        $this->assertCount(2, $call->args);
        $this->assertSame('bar($a, $b)', $call->args[0]);
        $this->assertSame('$c', $call->args[1]);
    }

    public function testCollectArgsHandlesArrayArguments(): void
    {
        $call = $this->extractSingleFunctionCall('<?php foo([$a, $b, $c], $d);');

        $this->assertSame('foo', $call->name);
        $this->assertCount(2, $call->args);
        $this->assertSame('[$a, $b, $c]', $call->args[0]);
        $this->assertSame('$d', $call->args[1]);
    }

    public function testCollectArgsHandlesAssociativeMultilineArrayArguments(): void
    {
        $call = $this->extractSingleFunctionCall(<<<'PHP'
<?php
wp_insert_post([
    'post_title' => $title,
    'post_content' => $content,
    'post_status' => 'publish',
    'post_type' => 'post',
], true);
PHP);

        $this->assertSame('wp_insert_post', $call->name);
        $this->assertCount(2, $call->args);
        $this->assertSame(str_replace("\n", PHP_EOL, "[\n    'post_title' => \$title,\n    'post_content' => \$content,\n    'post_status' => 'publish',\n    'post_type' => 'post',\n]"), $call->args[0]);
        $this->assertSame('true', $call->args[1]);
    }

    public function testCollectArgsHandlesNestedArrayArguments(): void
    {
        $call = $this->extractSingleFunctionCall(<<<'PHP'
<?php
foo([
    'one' => [$a, $b],
    'two' => ['x' => $c],
], $d);
PHP);

        $this->assertSame('foo', $call->name);
        $this->assertCount(2, $call->args);
        $this->assertSame(str_replace("\n", PHP_EOL, "[\n    'one' => [\$a, \$b],\n    'two' => ['x' => \$c],\n]"), $call->args[0]);
        $this->assertSame('$d', $call->args[1]);
    }

    public function testCollectArgsHandlesClosureArguments(): void
    {
        $call = $this->extractSingleFunctionCall(<<<'PHP'
<?php
foo(function () use ($a, $b) {
    return [$a, $b];
}, $c);
PHP);

        $this->assertSame('foo', $call->name);
        $this->assertCount(2, $call->args);
        $this->assertSame(str_replace("\n", PHP_EOL, "function () use (\$a, \$b) {\n    return [\$a, \$b];\n}"), $call->args[0]);
        $this->assertSame('$c', $call->args[1]);
    }

    public function testFunctionCallLineNumberRecorded(): void
    {
        $tokens = $this->tokenize("<?php\nfoo();");

        $result = $this->extractor->extract($tokens);

        $calls = array_filter(
            $result->functionCalls,
            static fn(FunctionCall $c) => $c->name === 'foo',
        );
        $this->assertNotEmpty($calls);
        $call = array_values($calls)[0];
        $this->assertSame(2, $call->line);
    }

    public function testMultipleFunctionCallsDetected(): void
    {
        $tokens = $this->tokenize('<?php foo(); bar(); baz();');

        $result = $this->extractor->extract($tokens);

        $names = array_map(static fn(FunctionCall $c) => $c->name, $result->functionCalls);
        $this->assertContains('foo', $names);
        $this->assertContains('bar', $names);
        $this->assertContains('baz', $names);
    }

    // ── dynamic dispatch ──────────────────────────────────────────────────────

    public function testVariableCallIsDynamic(): void
    {
        $tokens = $this->tokenize('<?php $fn("arg");');

        $result = $this->extractor->extract($tokens);

        $dynamicCalls = array_filter(
            $result->functionCalls,
            static fn(FunctionCall $c) => $c->isDynamic,
        );
        $this->assertNotEmpty($dynamicCalls);
    }

    public function testCallUserFuncIsDynamic(): void
    {
        $tokens = $this->tokenize('<?php call_user_func($fn, "arg");');

        $result = $this->extractor->extract($tokens);

        $calls = array_filter(
            $result->functionCalls,
            static fn(FunctionCall $c) => $c->name === 'call_user_func',
        );
        $this->assertNotEmpty($calls);
        $call = array_values($calls)[0];
        $this->assertTrue($call->isDynamic);
    }

    public function testCallUserFuncArrayIsDynamic(): void
    {
        $tokens = $this->tokenize('<?php call_user_func_array($fn, []);');

        $result = $this->extractor->extract($tokens);

        $calls = array_filter(
            $result->functionCalls,
            static fn(FunctionCall $c) => $c->name === 'call_user_func_array',
        );
        $this->assertNotEmpty($calls);
        $call = array_values($calls)[0];
        $this->assertTrue($call->isDynamic);
    }

    public function testRegularFunctionCallIsNotDynamic(): void
    {
        $tokens = $this->tokenize('<?php strlen("hello");');

        $result = $this->extractor->extract($tokens);

        $calls = array_filter(
            $result->functionCalls,
            static fn(FunctionCall $c) => $c->name === 'strlen',
        );
        $this->assertNotEmpty($calls);
        $call = array_values($calls)[0];
        $this->assertFalse($call->isDynamic);
    }

    // ── strings ───────────────────────────────────────────────────────────────

    public function testSingleQuotedStringExtracted(): void
    {
        $tokens = $this->tokenize("<?php \$x = 'hello';");

        $result = $this->extractor->extract($tokens);

        $strings = array_filter(
            $result->strings,
            static fn(ExtractedString $s) => $s->value === 'hello',
        );
        $this->assertNotEmpty($strings, "Expected 'hello' string to be extracted");
    }

    public function testDoubleQuotedStringExtracted(): void
    {
        $tokens = $this->tokenize('<?php $x = "world";');

        $result = $this->extractor->extract($tokens);

        $strings = array_filter(
            $result->strings,
            static fn(ExtractedString $s) => $s->value === 'world',
        );
        $this->assertNotEmpty($strings, 'Expected "world" string to be extracted');
    }

    public function testStringLineNumberRecorded(): void
    {
        $tokens = $this->tokenize("<?php\n\$x = 'test';");

        $result = $this->extractor->extract($tokens);

        $this->assertNotEmpty($result->strings);
        $str = $result->strings[0];
        $this->assertGreaterThanOrEqual(1, $str->line);
    }

    public function testShortBase64StringIsEncoded(): void
    {
        // 24 base64 chars — should match the base64 pattern.
        $b64 = 'SGVsbG8gV29ybGQhISEhISE=';
        $tokens = $this->tokenize("<?php \$x = '{$b64}';");

        $result = $this->extractor->extract($tokens);

        $encoded = array_filter(
            $result->strings,
            static fn(ExtractedString $s) => $s->isEncoded,
        );
        $this->assertNotEmpty($encoded, 'Expected encoded string to be flagged');
    }

    public function testPlainStringIsNotEncoded(): void
    {
        $tokens = $this->tokenize("<?php \$x = 'hello world';");

        $result = $this->extractor->extract($tokens);

        foreach ($result->strings as $str) {
            if ($str->value === 'hello world') {
                $this->assertFalse($str->isEncoded, "'hello world' should not be flagged as encoded");
                return;
            }
        }
        $this->fail('Expected string "hello world" to be extracted');
    }

    // ── variables ─────────────────────────────────────────────────────────────

    public function testVariableExtracted(): void
    {
        $tokens = $this->tokenize('<?php $myVar = 1;');

        $result = $this->extractor->extract($tokens);

        $vars = array_filter(
            $result->variables,
            static fn(VariableRef $v) => $v->name === '$myVar',
        );
        $this->assertNotEmpty($vars, 'Expected $myVar to be extracted');
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function userInputVarProvider(): array
    {
        return [
            '$_POST is user input'    => ['$_POST',    true],
            '$_GET is user input'     => ['$_GET',     true],
            '$_REQUEST is user input' => ['$_REQUEST', true],
            '$_COOKIE is user input'  => ['$_COOKIE',  true],
            '$_SERVER is user input'  => ['$_SERVER',  true],
            '$_FILES is user input'   => ['$_FILES',   true],
            '$myVar is not user input'=> ['$myVar',    false],
            '$foo is not user input'  => ['$foo',      false],
        ];
    }

    #[DataProvider('userInputVarProvider')]
    public function testUserInputFlag(string $varName, bool $expectedIsUserInput): void
    {
        $tokens = $this->tokenize("<?php \$x = {$varName};");

        $result = $this->extractor->extract($tokens);

        $vars = array_filter(
            $result->variables,
            static fn(VariableRef $v) => $v->name === $varName,
        );
        $this->assertNotEmpty($vars, "Expected {$varName} to be extracted");

        $var = array_values($vars)[0];
        $this->assertSame(
            $expectedIsUserInput,
            $var->isUserInput,
            "isUserInput for {$varName} should be " . ($expectedIsUserInput ? 'true' : 'false'),
        );
    }

    public function testVariableLineNumberRecorded(): void
    {
        $tokens = $this->tokenize("<?php\n\$x = 1;");

        $result = $this->extractor->extract($tokens);

        $vars = array_filter(
            $result->variables,
            static fn(VariableRef $v) => $v->name === '$x',
        );
        $this->assertNotEmpty($vars);
        $var = array_values($vars)[0];
        $this->assertSame(2, $var->line);
    }

    // ── include / require ─────────────────────────────────────────────────────

    /**
     * @return array<string, array{string, string}>
     */
    public static function importKeywordProvider(): array
    {
        return [
            'include'       => ["<?php include 'file.php';",       'include'],
            'include_once'  => ["<?php include_once 'file.php';",  'include_once'],
            'require'       => ["<?php require 'file.php';",        'require'],
            'require_once'  => ["<?php require_once 'file.php';",   'require_once'],
        ];
    }

    #[DataProvider('importKeywordProvider')]
    public function testImportKeywordDetected(string $source, string $expectedKeyword): void
    {
        $tokens = $this->tokenize($source);

        $result = $this->extractor->extract($tokens);

        $this->assertNotEmpty($result->imports, "Expected import statement to be detected for '{$source}'");
        $import = $result->imports[0];
        $this->assertInstanceOf(IncludeStatement::class, $import);
        $this->assertSame($expectedKeyword, $import->keyword);
    }

    public function testStaticImportIsNotDynamic(): void
    {
        $tokens = $this->tokenize("<?php require_once 'config.php';");

        $result = $this->extractor->extract($tokens);

        $this->assertNotEmpty($result->imports);
        $import = $result->imports[0];
        $this->assertFalse($import->isDynamic);
    }

    public function testDynamicImportIsFlagged(): void
    {
        $tokens = $this->tokenize('<?php include $path;');

        $result = $this->extractor->extract($tokens);

        $this->assertNotEmpty($result->imports);
        $import = $result->imports[0];
        $this->assertTrue($import->isDynamic);
    }

    public function testImportPathContainsExpression(): void
    {
        $tokens = $this->tokenize("<?php require 'vendor/' . \$name . '.php';");

        $result = $this->extractor->extract($tokens);

        $this->assertNotEmpty($result->imports);
        $import = $result->imports[0];
        // Path should be non-empty and contain the partial string.
        $this->assertNotEmpty($import->path);
        $this->assertTrue($import->isDynamic, 'Concatenated path with variable should be dynamic');
    }

    public function testImportLineNumberRecorded(): void
    {
        $tokens = $this->tokenize("<?php\nrequire 'file.php';");

        $result = $this->extractor->extract($tokens);

        $this->assertNotEmpty($result->imports);
        $import = $result->imports[0];
        $this->assertSame(2, $import->line);
    }

    // ── combined source ───────────────────────────────────────────────────────

    public function testAllFeaturesExtractedFromMixedSource(): void
    {
        $source = <<<'PHP'
            <?php
            require_once 'bootstrap.php';
            $data = $_POST['input'];
            $result = base64_decode($data);
            eval($result);
            PHP;

        $tokens  = $this->tokenize($source);
        $result  = $this->extractor->extract($tokens);

        // At least one import
        $this->assertNotEmpty($result->imports);

        // At least one user-input variable
        $userInputVars = array_filter(
            $result->variables,
            static fn(VariableRef $v) => $v->isUserInput,
        );
        $this->assertNotEmpty($userInputVars);

        // base64_decode and eval should be detected as function calls
        $callNames = array_map(static fn(FunctionCall $c) => $c->name, $result->functionCalls);
        $this->assertContains('base64_decode', $callNames);
        $this->assertContains('eval', $callNames);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /**
     * Tokenize a PHP snippet and return the token array.
     *
     * @return \Wpma\Models\Token[]
     */
    private function tokenize(string $source): array
    {
        return $this->tokenizer->tokenize($source)->tokens;
    }

    private function extractSingleFunctionCall(string $source): FunctionCall
    {
        $result = $this->extractor->extract($this->tokenize($source));
        $this->assertCount(1, $result->functionCalls);

        return $result->functionCalls[0];
    }
}
