<?php

declare(strict_types=1);

namespace Wpma\Pipeline;

use Wpma\Models\AnalysisObject;
use Wpma\Models\FileFeatures;
use Wpma\Models\FileMeta;
use Wpma\Models\ParseError;
use Wpma\Models\WPContext;

/**
 * PipelineRunner — assembles the full per-file analysis pipeline.
 *
 * Order: read → detect encoding → tokenize → extract tokens → extract features → extract IOCs → AnalysisObject
 *
 * Never throws — all errors are recorded in parseErrors.
 */
class PipelineRunner
{
    public function __construct(
        private readonly PhpTokenizer    $tokenizer      = new PhpTokenizer(),
        private readonly TokenExtractor  $tokenExtractor = new TokenExtractor(),
        private readonly FeatureExtractor $featureExtractor = new FeatureExtractor(),
        private readonly IOCExtractor    $iocExtractor   = new IOCExtractor(),
    ) {}

    /**
     * Run the full pipeline on a single file.
     *
     * @param string      $filePath     Absolute path to the file.
     * @param string      $scanRoot     Scan root path (for relativePath computation).
     * @param ?WPContext  $wpContext    Pre-classified WordPress context (optional).
     */
    public function run(string $filePath, string $scanRoot = '', ?WPContext $wpContext = null): AnalysisObject
    {
        $parseErrors = [];
        $startMs     = microtime(true) * 1000;

        // ── 1. Read file ──────────────────────────────────────────────────────
        $rawBytes = '';
        try {
            $rawBytes = @file_get_contents($filePath);
            if ($rawBytes === false) {
                $rawBytes = '';
                $parseErrors[] = new ParseError("Cannot read file: {$filePath}", 0, '');
            }
        } catch (\Throwable $e) {
            $parseErrors[] = new ParseError("Read error: " . $e->getMessage(), 0, '');
        }

        // ── 2. Encoding detection ─────────────────────────────────────────────
        $encoding = 'UTF-8';
        if (!empty($rawBytes)) {
            $detected = mb_detect_encoding($rawBytes, ['UTF-8', 'ISO-8859-1', 'Windows-1252'], true);
            if ($detected !== false) {
                $encoding = $detected;
            }
            if ($encoding !== 'UTF-8') {
                $converted = mb_convert_encoding($rawBytes, 'UTF-8', $encoding);
                $rawContent = $converted !== false ? $converted : $rawBytes;
            } else {
                $rawContent = $rawBytes;
            }
        } else {
            $rawContent = '';
        }

        // ── 3. Tokenize ───────────────────────────────────────────────────────
        $tokens      = [];
        $ext         = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        $isPHP       = in_array($ext, ['php', 'phtml', 'php5', 'php7', 'phar'], true);

        if ($isPHP && !empty($rawContent)) {
            try {
                $tokenizeResult = $this->tokenizer->tokenize($rawContent, $filePath);
                $tokens         = $tokenizeResult->tokens;
                foreach ($tokenizeResult->parseErrors as $err) {
                    $parseErrors[] = $err;
                }
            } catch (\Throwable $e) {
                $parseErrors[] = new ParseError("Tokenize error: " . $e->getMessage(), 0, '');
            }
        }

        // ── 4. Token extraction ───────────────────────────────────────────────
        $functionCalls = [];
        $strings       = [];
        $variables     = [];
        $imports       = [];
        $assignments   = [];

        if (!empty($tokens)) {
            try {
                $extracted     = $this->tokenExtractor->extract($tokens);
                $functionCalls = $extracted->functionCalls;
                $strings       = $extracted->strings;
                $variables     = $extracted->variables;
                $imports       = $extracted->imports;
                $assignments   = $extracted->assignments;
            } catch (\Throwable $e) {
                $parseErrors[] = new ParseError("Token extraction error: " . $e->getMessage(), 0, '');
            }
        }

        // ── 5. Feature extraction ─────────────────────────────────────────────
        $features = new FileFeatures();
        try {
            $features = $this->featureExtractor->extract($tokens, $rawContent);
        } catch (\Throwable $e) {
            $parseErrors[] = new ParseError("Feature extraction error: " . $e->getMessage(), 0, '');
        }

        // ── 6. IOC extraction ─────────────────────────────────────────────────
        $iocs = [];
        try {
            $iocs = $this->iocExtractor->extract($rawContent, $filePath);
        } catch (\Throwable $e) {
            $parseErrors[] = new ParseError("IOC extraction error: " . $e->getMessage(), 0, '');
        }

        // ── 7. Build FileMeta ─────────────────────────────────────────────────
        $dotExt      = $ext !== '' ? '.' . $ext : '';
        $fileSize    = strlen($rawBytes);
        $lineCount   = substr_count($rawContent, "\n") + 1;
        $relativePath = $scanRoot !== ''
            ? ltrim(str_replace(str_replace('\\', '/', $scanRoot), '', str_replace('\\', '/', $filePath)), '/')
            : basename($filePath);

        $meta = new FileMeta(
            filePath:     $filePath,
            relativePath: $relativePath,
            fileSize:     $fileSize,
            extension:    $dotExt,
            encoding:     $encoding,
            lineCount:    $lineCount,
            scanTimeMs:   round((microtime(true) * 1000) - $startMs, 2),
            wpContext:    $wpContext,
        );

        return new AnalysisObject(
            meta:          $meta,
            rawContent:    $rawContent,
            tokens:        $tokens,
            functionCalls: $functionCalls,
            strings:       $strings,
            variables:     $variables,
            imports:       $imports,
            assignments:   $assignments,
            iocs:          $iocs,
            features:      $features,
            parseErrors:   $parseErrors,
        );
    }
}
