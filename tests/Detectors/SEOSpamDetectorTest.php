<?php

declare(strict_types=1);

namespace Wpma\Tests\Detectors;

use PHPUnit\Framework\TestCase;
use Wpma\Detectors\SEOSpamDetector;
use Wpma\Models\AnalysisObject;
use Wpma\Models\FileFeatures;
use Wpma\Models\FileMeta;
use Wpma\Models\IOC;
use Wpma\Models\IOCType;
use Wpma\Pipeline\PhpTokenizer;
use Wpma\Pipeline\TokenExtractor;

final class SEOSpamDetectorTest extends TestCase
{
    private SEOSpamDetector $detector;
    private PhpTokenizer $tokenizer;
    private TokenExtractor $extractor;

    protected function setUp(): void
    {
        parent::setUp();
        $this->detector = new SEOSpamDetector();
        $this->tokenizer = new PhpTokenizer();
        $this->extractor = new TokenExtractor();
    }

    public function testMaliciousMassSpamFixtureRemainsDetected(): void
    {
        $source = <<<'PHP'
<?php
$spam = base64_decode($_POST['content']);
for ($i = 0; $i < 100; $i++) {
    wp_insert_post([
        'post_title'   => 'Cheap Online Casino ' . $i,
        'post_content' => $spam,
        'post_status'  => 'publish',
        'post_type'    => 'post',
    ]);
}
PHP;

        $findings = $this->detector->detect($this->makeAoFromSource($source));

        $this->assertCount(1, $this->filterSeo008($findings));
    }

    public function testStatusOnlyUpdateIsNotDetected(): void
    {
        $source = <<<'PHP'
<?php
wp_update_post([
    'ID' => $id,
    'post_status' => 'request-completed',
]);
PHP;

        $findings = $this->detector->detect($this->makeAoFromSource($source));

        $this->assertCount(0, $this->filterSeo008($findings));
    }

    public function testUnrelatedFileWideLoopIsNotCorrelated(): void
    {
        $source = <<<'PHP'
<?php
foreach ($items as $item) {
    log_item($item);
}
wp_insert_post([
    'post_title' => 'Welcome Page',
    'post_content' => 'Legitimate content for visitors.',
    'post_status' => 'publish',
    'post_type' => 'page',
]);
PHP;

        $findings = $this->detector->detect($this->makeAoFromSource($source));

        $this->assertCount(0, $this->filterSeo008($findings));
    }

    public function testUnrelatedSpamKeywordIsNotCorrelated(): void
    {
        $source = <<<'PHP'
<?php
$note = 'casino';
wp_insert_post([
    'post_title' => 'Welcome Page',
    'post_content' => 'Legitimate content for visitors.',
    'post_status' => 'publish',
    'post_type' => 'page',
]);
PHP;

        $findings = $this->detector->detect($this->makeAoFromSource($source));

        $this->assertCount(0, $this->filterSeo008($findings));
    }

    public function testUnrelatedUrlIocIsNotCorrelated(): void
    {
        $source = <<<'PHP'
<?php
$doc = 'http://attacker.example/doc';
wp_insert_post([
    'post_title' => 'Welcome Page',
    'post_content' => 'Legitimate content for visitors.',
    'post_status' => 'publish',
    'post_type' => 'page',
]);
PHP;

        $findings = $this->detector->detect($this->makeAoFromSource($source));

        $this->assertCount(0, $this->filterSeo008($findings));
    }

    public function testAttackerControlledContentFlowIsDetected(): void
    {
        $source = <<<'PHP'
<?php
$spam = $_POST['content'];
for ($i = 0; $i < 50; $i++) {
    wp_insert_post([
        'post_title' => 'Cheap Online Casino ' . $i,
        'post_content' => $spam,
        'post_status' => 'publish',
        'post_type' => 'post',
    ]);
}
PHP;

        $findings = $this->detector->detect($this->makeAoFromSource($source));

        $this->assertCount(1, $this->filterSeo008($findings));
    }

    public function testMultipleMutationCallsEvaluatedIndependently(): void
    {
        $source = <<<'PHP'
<?php
wp_update_post([
    'ID' => $id,
    'post_status' => 'draft',
]);

$spam = base64_decode($_POST['content']);
for ($i = 0; $i < 10; $i++) {
    wp_insert_post([
        'post_title' => 'Cheap Online Casino ' . $i,
        'post_content' => $spam,
        'post_status' => 'publish',
        'post_type' => 'post',
    ]);
}
PHP;

        $findings = $this->filterSeo008($this->detector->detect($this->makeAoFromSource($source)));

        $this->assertCount(1, $findings);
        $this->assertSame(9, $findings[0]->line);
    }

    /**
     * @return array
     */
    private function filterSeo008(array $findings): array
    {
        return array_values(array_filter($findings, static fn ($finding): bool => $finding->ruleId === 'SEO-008'));
    }

    private function makeAoFromSource(string $source): AnalysisObject
    {
        $tokenizeResult = $this->tokenizer->tokenize($source, 'fixture.php');
        $extractResult = $this->extractor->extract($tokenizeResult->tokens);
        $iocs = $this->extractIocsFromSource($source);

        return new AnalysisObject(
            meta: new FileMeta(
                filePath: 'fixture.php',
                relativePath: 'fixture.php',
                fileSize: strlen($source),
                extension: '.php',
                encoding: 'UTF-8',
                lineCount: substr_count($source, "\n") + 1,
                scanTimeMs: 0.0,
                wpContext: null,
            ),
            rawContent: $source,
            tokens: $tokenizeResult->tokens,
            functionCalls: $extractResult->functionCalls,
            strings: $extractResult->strings,
            variables: $extractResult->variables,
            imports: $extractResult->imports,
            assignments: $extractResult->assignments,
            iocs: $iocs,
            features: new FileFeatures(
                encodedBlobs: [],
                dynamicDispatchCalls: [],
                userInputSources: [],
                networkCalls: [],
                fileWriteCalls: [],
                obfuscationScore: 0.0,
                entropyScore: 0.0,
                taintPaths: [],
            ),
            parseErrors: $tokenizeResult->parseErrors,
        );
    }

    /**
     * @return IOC[]
     */
    private function extractIocsFromSource(string $source): array
    {
        $iocs = [];
        $lines = explode("\n", $source);

        foreach ($lines as $index => $line) {
            if (preg_match_all('#https?://[^\s\'"<>)}\]]+#', $line, $matches)) {
                foreach ($matches[0] as $url) {
                    $host = parse_url($url, PHP_URL_HOST) ?: '';
                    $iocs[] = new IOC(
                        type: IOCType::URL,
                        value: $url,
                        filePath: 'fixture.php',
                        line: $index + 1,
                        isPrivateIp: false,
                        isKnownWpService: false,
                    );
                    if ($host !== '') {
                        $iocs[] = new IOC(
                            type: IOCType::DOMAIN,
                            value: $host,
                            filePath: 'fixture.php',
                            line: $index + 1,
                            isPrivateIp: false,
                            isKnownWpService: false,
                        );
                    }
                }
            }
        }

        return $iocs;
    }
}
