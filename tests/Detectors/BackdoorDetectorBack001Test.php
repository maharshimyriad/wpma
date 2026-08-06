<?php

declare(strict_types=1);

namespace Wpma\Tests\Detectors;

use PHPUnit\Framework\TestCase;
use Wpma\Detectors\BackdoorDetector;
use Wpma\Models\AnalysisObject;
use Wpma\Models\FileFeatures;
use Wpma\Models\FileMeta;
use Wpma\Models\FunctionCall;
use Wpma\Models\VariableAssignment;
use Wpma\Models\VariableRef;

final class BackdoorDetectorBack001Test extends TestCase
{
    private BackdoorDetector $detector;

    protected function setUp(): void
    {
        parent::setUp();
        $this->detector = new BackdoorDetector();
    }

    public function testSystemWithDirectGetIsDetected(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('system', ["\$_GET['cmd']"], 3, false)],
            variables: [new VariableRef('$_GET', 3, true)],
        );

        $this->assertCount(1, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testExecWithPostDerivedVariableIsDetected(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('exec', ['$cmd'], 4, false)],
            assignments: [new VariableAssignment('$cmd', 2, "\$_POST['cmd']", [], true)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(1, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testPopenWithDirectRequestIsDetected(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('popen', ["\$_REQUEST['command']", "'r'"], 5, false)],
            variables: [new VariableRef('$_REQUEST', 5, true)],
        );

        $this->assertCount(1, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testPopenWithConfiguredPathIsNotDetectedWithoutSuspiciousProvenance(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('popen', ['$sendmail', "'w'"], 6, false)],
            assignments: [new VariableAssignment('$sendmail', 4, 'trim(escapeshellcmd($configuredPath))', ['trim', 'escapeshellcmd'], false)],
        );

        $this->assertCount(0, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testCallUserFuncWithDirectRequestCallbackIsDetected(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('call_user_func', ["\$_REQUEST['function']", "\$_POST['payload']"], 7, true)],
            variables: [
                new VariableRef('$_REQUEST', 7, true),
                new VariableRef('$_POST', 7, true),
            ],
        );

        $this->assertCount(1, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testCallUserFuncWithPostDerivedCallbackVariableIsDetected(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('call_user_func', ['$callback', '$payload'], 8, true)],
            assignments: [new VariableAssignment('$callback', 3, "\$_POST['callback']", [], true)],
            variables: [new VariableRef('$_POST', 3, true)],
        );

        $this->assertCount(1, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testCallUserFuncWithTransitiveRequestDerivedCallbackVariableIsDetected(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('call_user_func', ['$b', '$data'], 9, true)],
            assignments: [
                new VariableAssignment('$a', 2, "\$_REQUEST['callback']", [], true),
                new VariableAssignment('$b', 3, '$a', [], false),
            ],
            variables: [new VariableRef('$_REQUEST', 2, true)],
        );

        $this->assertCount(1, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testDirectCompoundCallbackExpressionIsNotDetectedFromContainerTaint(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('call_user_func', ['$form[\'callback\']', '$form[\'params\']'], 10, true)],
            assignments: [new VariableAssignment('$form', 4, "\$_POST['form']", [], true)],
            variables: [new VariableRef('$_POST', 4, true)],
        );

        $this->assertCount(0, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testBareCallbackAssignedFromExporterMemberIsNotDetectedWhenMemberProvenanceIsUnknown(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('call_user_func', ['$callback', '$email'], 11, true)],
            assignments: [
                new VariableAssignment('$exporter', 3, "\$_POST['exporter']", [], true),
                new VariableAssignment('$callback', 4, '$exporter[\'callback\']', [], false),
            ],
            variables: [new VariableRef('$_POST', 3, true)],
        );

        $this->assertCount(0, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testBareCallbackAssignedFromEraserMemberIsNotDetectedWhenMemberProvenanceIsUnknown(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('call_user_func', ['$callback', '$email'], 12, true)],
            assignments: [
                new VariableAssignment('$eraser', 3, "\$_POST['eraser']", [], true),
                new VariableAssignment('$callback', 4, '$eraser[\'callback\']', [], false),
            ],
            variables: [new VariableRef('$_POST', 3, true)],
        );

        $this->assertCount(0, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testStaticSodiumHex2binCallbackIsNotDetected(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('call_user_func', ["'\\\\Sodium\\\\hex2bin'", '$string', '$ignore'], 9, false)],
            features: new FileFeatures(obfuscationScore: 0.9, encodedBlobs: ['AAAAABBBBBCCCCCDDDDDEEEEEFFFFF']),
        );

        $this->assertCount(0, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testStaticPackCallbackIsNotDetectedFromFileWideObfuscation(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('call_user_func_array', ["'pack'", '$args'], 10, false)],
            features: new FileFeatures(obfuscationScore: 0.9, encodedBlobs: ['AAAAABBBBBCCCCCDDDDDEEEEEFFFFF']),
        );

        $this->assertCount(0, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testUnrelatedUserInputElsewhereDoesNotCorrelateWithSafeCommandVariable(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('exec', ['$cmd'], 11, false)],
            assignments: [new VariableAssignment('$cmd', 4, "'/usr/bin/convert image.jpg'", [], false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(0, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testUnrelatedEncodedContentElsewhereDoesNotCorrelateWithStaticCallback(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('call_user_func', ["'known_function'", '$value'], 13, false)],
            features: new FileFeatures(obfuscationScore: 0.9, encodedBlobs: ['AAAAABBBBBCCCCCDDDDDEEEEEFFFFF']),
        );

        $this->assertCount(0, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testEvalWithDirectPostIsDetected(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('eval', ["\$_POST['code']"], 14, false)],
            variables: [new VariableRef('$_POST', 14, true)],
        );

        $this->assertCount(1, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testEvalWithPostDerivedVariableIsDetected(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('eval', ['$code'], 15, false)],
            assignments: [new VariableAssignment('$code', 2, "\$_POST['code']", [], true)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(1, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testEvalWithBase64DecodedPostDerivedVariableIsDetected(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('eval', ['$code'], 16, false)],
            assignments: [new VariableAssignment('$code', 2, "base64_decode(\$_POST['code'])", ['base64_decode'], true)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(1, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testEvalWithTransitiveDecodedRequestDerivedVariableIsDetected(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('eval', ['$b'], 17, false)],
            assignments: [
                new VariableAssignment('$a', 2, "\$_REQUEST['x']", [], true),
                new VariableAssignment('$b', 3, 'base64_decode($a)', ['base64_decode'], false),
            ],
            variables: [new VariableRef('$_REQUEST', 2, true)],
        );

        $this->assertCount(1, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testEvalWithDirectNestedDecodedPostIsDetected(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('eval', ["base64_decode(\$_POST['code'])"], 18, false)],
            variables: [new VariableRef('$_POST', 18, true)],
        );

        $this->assertCount(1, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testAssertWithDirectRequestIsDetected(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('assert', ["\$_REQUEST['code']"], 19, false)],
            variables: [new VariableRef('$_REQUEST', 19, true)],
        );

        $this->assertCount(1, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testAssertWithPostDerivedVariableIsDetected(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('assert', ['$code'], 20, false)],
            assignments: [new VariableAssignment('$code', 2, "\$_POST['code']", [], true)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(1, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testEvalWithNullCoalescingDirectPostIsDetected(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('eval', ["\$_POST['code'] ?? ''"], 21, false)],
            variables: [new VariableRef('$_POST', 21, true)],
        );

        $this->assertCount(1, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testEvalWithNullCoalescingDecodedPostDerivedVariableIsDetected(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('eval', ['$code'], 22, false)],
            assignments: [new VariableAssignment('$code', 2, "base64_decode(\$_POST['code'] ?? '')", ['base64_decode'], true)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(1, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testEvalWithStaticLiteralIsNotDetected(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('eval', ["'\$value = 1 + 2;'"], 23, false)],
        );

        $this->assertCount(0, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testEvalWithTrustedGeneratedCodeVariableIsNotDetected(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('eval', ['$code'], 24, false)],
            assignments: [new VariableAssignment('$code', 2, 'getTrustedLocalGeneratedCode()', ['getTrustedLocalGeneratedCode'], false)],
        );

        $this->assertCount(0, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testEvalWithStaticStringVariableIsNotDetected(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('eval', ['$code'], 25, false)],
            assignments: [new VariableAssignment('$code', 2, "'echo \"test\";'", [], false)],
        );

        $this->assertCount(0, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testDecodeWithoutExecutionIsNotDetectedByBack001(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('process', ['$data'], 26, false)],
            assignments: [new VariableAssignment('$data', 2, 'base64_decode($storedData)', ['base64_decode'], false)],
        );

        $this->assertCount(0, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testUnrelatedUserInputElsewhereDoesNotCorrelateWithStaticEval(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('eval', ["'\$value = 123;'"], 27, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(0, $this->filterBack001($this->detector->detect($ao)));
    }

    public function testUnrelatedDecodeElsewhereDoesNotCorrelateWithStaticEval(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('eval', ["'\$value = 123;'"], 28, false)],
            assignments: [new VariableAssignment('$data', 2, "base64_decode(\$_POST['data'])", ['base64_decode'], true)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(0, $this->filterBack001($this->detector->detect($ao)));
    }

    /**
     * @param FunctionCall[] $calls
     * @param VariableAssignment[] $assignments
     * @param VariableRef[] $variables
     */
    private function makeAo(
        array $calls,
        array $assignments = [],
        array $variables = [],
        ?FileFeatures $features = null,
    ): AnalysisObject {
        return new AnalysisObject(
            meta: new FileMeta(
                filePath: '/test/file.php',
                relativePath: 'file.php',
                fileSize: 100,
                extension: '.php',
                encoding: 'UTF-8',
                lineCount: 20,
                scanTimeMs: 0.0,
            ),
            rawContent: '<?php // test',
            tokens: [],
            functionCalls: $calls,
            strings: [],
            variables: $variables,
            imports: [],
            assignments: $assignments,
            iocs: [],
            features: $features ?? new FileFeatures(),
            parseErrors: [],
        );
    }

    private function filterBack001(array $findings): array
    {
        return array_values(array_filter($findings, static fn ($finding): bool => $finding->ruleId === 'BACK-001'));
    }
}
