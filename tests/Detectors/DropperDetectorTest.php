<?php

declare(strict_types=1);

namespace Wpma\Tests\Detectors;

use PHPUnit\Framework\TestCase;
use Wpma\Detectors\DropperDetector;
use Wpma\Models\AnalysisObject;
use Wpma\Models\FileFeatures;
use Wpma\Models\FileMeta;
use Wpma\Models\FunctionCall;
use Wpma\Models\VariableAssignment;
use Wpma\Models\VariableRef;

final class DropperDetectorTest extends TestCase
{
    private DropperDetector $detector;

    protected function setUp(): void
    {
        parent::setUp();
        $this->detector = new DropperDetector();
    }

    public function testAssignedMaliciousDecoderWriteIsDetected(): void
    {
        $ao = $this->makeAo(
            calls: [
                new FunctionCall('base64_decode', ["\$_POST['payload'] ?? ''"], 2, false),
                new FunctionCall('file_put_contents', ["__DIR__ . '/dropped.php'", '$payload'], 3, false),
            ],
            assignments: [
                new VariableAssignment('$payload', 2, "base64_decode(\$_POST['payload'] ?? '')", ['base64_decode'], true),
            ],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $findings = $this->filterDrop002($this->detector->detect($ao));
        $this->assertCount(1, $findings);
        $this->assertSame('DROP-002', $findings[0]->ruleId);
    }

    public function testInlineMaliciousDecoderWriteIsDetected(): void
    {
        $ao = $this->makeAo(
            calls: [
                new FunctionCall('file_put_contents', ["__DIR__ . '/dropped.php'", "base64_decode(\$_REQUEST['data'] ?? '')"], 2, false),
            ],
            variables: [new VariableRef('$_REQUEST', 2, true)],
        );

        $findings = $this->filterDrop002($this->detector->detect($ao));
        $this->assertCount(1, $findings);
        $this->assertSame('DROP-002', $findings[0]->ruleId);
    }

    public function testUnrelatedDecodeAndWriteIsNotDetected(): void
    {
        $ao = $this->makeAo(
            calls: [
                new FunctionCall('base64_decode', ['$something'], 2, false),
                new FunctionCall('file_put_contents', ['$path', '$normalContent'], 3, false),
            ],
            assignments: [
                new VariableAssignment('$decoded', 2, 'base64_decode($something)', ['base64_decode'], false),
                new VariableAssignment('$normalContent', 3, "'normal'", [], false),
            ],
        );

        $this->assertCount(0, $this->filterDrop002($this->detector->detect($ao)));
    }

    public function testWriteWithoutDecoderIsNotDetected(): void
    {
        $ao = $this->makeAo(
            calls: [
                new FunctionCall('file_put_contents', ['$path', "\$_POST['data']"], 2, false),
            ],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(0, $this->filterDrop002($this->detector->detect($ao)));
    }

    public function testLegitimateDecompressionExtractionRemainsClean(): void
    {
        $ao = $this->makeAo(
            calls: [
                new FunctionCall('gzinflate', ['$localArchiveData'], 2, false),
                new FunctionCall('file_put_contents', ["'/tmp/output.bin'", '$data'], 3, false),
            ],
            assignments: [
                new VariableAssignment('$data', 2, 'gzinflate($localArchiveData)', ['gzinflate'], false),
                new VariableAssignment('$localArchiveData', 1, '$archiveBytes', [], false),
            ],
        );

        $this->assertCount(0, $this->filterDrop002($this->detector->detect($ao)));
    }

    public function testDrop003DetectsLiteralExecutablePath(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('file_put_contents', ["'/tmp/shell.php'", "base64_decode(\$_POST['data'])"], 2, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $findings = $this->filterDrop003($this->detector->detect($ao));
        $this->assertCount(1, $findings);
    }

    public function testDrop003DetectsDirMagicConcatenationExecutablePath(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('file_put_contents', ["__DIR__ . '/shell.php'", "base64_decode(\$_POST['data'])"], 2, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $findings = $this->filterDrop003($this->detector->detect($ao));
        $this->assertCount(1, $findings);
    }

    public function testDrop003DetectsAbspathConcatenationExecutablePath(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('file_put_contents', ["ABSPATH . 'shell.php'", "base64_decode(\$_POST['data'])"], 2, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $findings = $this->filterDrop003($this->detector->detect($ao));
        $this->assertCount(1, $findings);
    }

    public function testDrop003DetectsDirnameMagicConcatenationExecutablePath(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('file_put_contents', ["dirname(__FILE__) . '/shell.php'", "base64_decode(\$_POST['data'])"], 2, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $findings = $this->filterDrop003($this->detector->detect($ao));
        $this->assertCount(1, $findings);
    }

    public function testDrop003DetectsConcatenatedLiteralExecutablePath(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('file_put_contents', ["'/tmp/' . 'shell.php'", "base64_decode(\$_POST['data'])"], 2, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $findings = $this->filterDrop003($this->detector->detect($ao));
        $this->assertCount(1, $findings);
    }

    public function testDrop003DetectsAdditionalExecutableExtensions(): void
    {
        $ao1 = $this->makeAo(
            calls: [new FunctionCall('file_put_contents', ["__DIR__ . '/shell.phtml'", "base64_decode(\$_POST['data'])"], 2, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );
        $ao2 = $this->makeAo(
            calls: [new FunctionCall('file_put_contents', ["__DIR__ . '/shell.php5'", "base64_decode(\$_POST['data'])"], 2, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(1, $this->filterDrop003($this->detector->detect($ao1)));
        $this->assertCount(1, $this->filterDrop003($this->detector->detect($ao2)));
    }

    public function testDrop003DoesNotTreatPhpSubstringBeforeFinalExtensionAsExecutable(): void
    {
        $ao1 = $this->makeAo(
            calls: [new FunctionCall('file_put_contents', ["__DIR__ . '/shell.php.txt'", "\$_POST['data']"], 2, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );
        $ao2 = $this->makeAo(
            calls: [new FunctionCall('file_put_contents', ["__DIR__ . '/shell.php' . '.txt'", "\$_POST['data']"], 2, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(0, $this->filterDrop003($this->detector->detect($ao1)));
        $this->assertCount(0, $this->filterDrop003($this->detector->detect($ao2)));
    }

    public function testDrop003DoesNotTreatIntermediatePhpSubstringAsExecutable(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('file_put_contents', ["'/shell.php/' . \$name", "\$_POST['data']"], 2, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(0, $this->filterDrop003($this->detector->detect($ao)));
    }

    public function testDrop003DoesNotDetectFullyDynamicDestinations(): void
    {
        $ao1 = $this->makeAo(
            calls: [new FunctionCall('file_put_contents', ['$path', "\$_POST['data']"], 2, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );
        $ao2 = $this->makeAo(
            calls: [new FunctionCall('file_put_contents', ['$tempPath', "\$_POST['data']"], 2, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );
        $ao3 = $this->makeAo(
            calls: [new FunctionCall('file_put_contents', ["\$_POST['path']", "\$_POST['data']"], 2, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );
        $ao4 = $this->makeAo(
            calls: [new FunctionCall('file_put_contents', ['$dir . $filename', "\$_POST['data']"], 2, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );
        $ao5 = $this->makeAo(
            calls: [new FunctionCall('file_put_contents', ['\$dir . ' . "\$_POST['filename']", "\$_POST['data']"], 2, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );
        $ao6 = $this->makeAo(
            calls: [new FunctionCall('file_put_contents', ['\$dir . \'/shell.php\' . \$suffix', "\$_POST['data']"], 2, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(0, $this->filterDrop003($this->detector->detect($ao1)));
        $this->assertCount(0, $this->filterDrop003($this->detector->detect($ao2)));
        $this->assertCount(0, $this->filterDrop003($this->detector->detect($ao3)));
        $this->assertCount(0, $this->filterDrop003($this->detector->detect($ao4)));
        $this->assertCount(0, $this->filterDrop003($this->detector->detect($ao5)));
        $this->assertCount(0, $this->filterDrop003($this->detector->detect($ao6)));
    }

    public function testDrop003RequestControlledContentToFixedExecutablePathIsDetected(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('file_put_contents', ["'/var/www/html/output.php'", "\$_POST['data']"], 2, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $findings = $this->filterDrop003($this->detector->detect($ao));
        $this->assertCount(1, $findings);
        $this->assertSame('DROP-003', $findings[0]->ruleId);
    }

    public function testDrop003RequestControlledContentToDirPhpPathIsDetected(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('file_put_contents', ["__DIR__ . '/output.php'", '$data'], 3, false)],
            assignments: [new VariableAssignment('$data', 2, "\$_POST['data'] ?? ''", [], true)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $findings = $this->filterDrop003($this->detector->detect($ao));
        $this->assertCount(1, $findings);
        $this->assertSame('DROP-003', $findings[0]->ruleId);
    }

    public function testDrop003BenignTxtWriteDoesNotEmitFromExecutablePathLogic(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('file_put_contents', ["__DIR__ . '/output.txt'", '$data'], 3, false)],
            assignments: [new VariableAssignment('$data', 2, "\$_POST['data'] ?? ''", [], true)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(0, $this->filterDrop003($this->detector->detect($ao)));
    }

    public function testDrop003DoesNotDetectRequestControlledWriteToNonExecutablePath(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('file_put_contents', ["'/tmp/data.txt'", "\$_POST['data']"], 2, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(0, $this->filterDrop003($this->detector->detect($ao)));
    }

    public function testDrop003DoesNotDetectRequestControlledWriteToUnresolvedDynamicDestination(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('file_put_contents', ['$userControlledPath', "\$_POST['data']"], 2, false)],
            variables: [new VariableRef('$_POST', 2, true)],
        );

        $this->assertCount(0, $this->filterDrop003($this->detector->detect($ao)));
    }

    public function testDrop003DoesNotDetectTrustedContentToExecutablePath(): void
    {
        $ao = $this->makeAo(
            calls: [new FunctionCall('file_put_contents', ["__DIR__ . '/output.php'", 'trusted_local_content()'], 2, false)],
        );

        $this->assertCount(0, $this->filterDrop003($this->detector->detect($ao)));
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
        string $filePath = '/test/file.php',
    ): AnalysisObject {
        $ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));

        return new AnalysisObject(
            meta: new FileMeta(
                filePath: $filePath,
                relativePath: basename($filePath),
                fileSize: 100,
                extension: $ext !== '' ? '.' . $ext : '.php',
                encoding: 'UTF-8',
                lineCount: 10,
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
            features: new FileFeatures(),
            parseErrors: [],
        );
    }

    private function filterDrop002(array $findings): array
    {
        return array_values(array_filter($findings, static fn ($finding): bool => $finding->ruleId === 'DROP-002'));
    }

    private function filterDrop003(array $findings): array
    {
        return array_values(array_filter($findings, static fn ($finding): bool => $finding->ruleId === 'DROP-003'));
    }
}
