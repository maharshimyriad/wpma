<?php

declare(strict_types=1);

namespace Wpma\Detectors;

use Wpma\Models\AnalysisObject;
use Wpma\Models\EvidenceItem;
use Wpma\Models\Finding;

/**
 * AbstractDetector — base class that defines the Detector interface all concrete detectors implement.
 *
 * Every concrete detector must implement:
 *  - getName()              — unique string identifier for this detector/rule set
 *  - getVersion()           — semver version string for this detector
 *  - getRuleId()            — base rule ID prefix (e.g. 'OBF', 'BACK')
 *  - getSupportedExtensions() — list of file extensions (or ['*'] for all)
 *  - detect()               — core detection logic; receives AnalysisObject, returns Finding[]
 *
 * Concrete methods provided by this class:
 *  - isApplicable()         — uses getSupportedExtensions() to filter by extension
 *  - safeDetect()           — wraps detect() in try/catch; returns [] on exception
 *
 * Requirements: 3.1 (Detector interface), 3.2 (receives AnalysisObject, returns Findings),
 *               3.4 (declares supported file types).
 */
abstract class AbstractDetector implements DetectorInterface
{
    /**
     * Returns a unique string identifier for this detector / rule set.
     *
     * Example: 'ObfuscationDetector', 'BackdoorDetector'
     */
    abstract public function getName(): string;

    /**
     * Returns the semver-style version string for this detector.
     *
     * Example: '1.0.0'
     */
    abstract public function getVersion(): string;

    /**
     * Returns the base rule ID prefix for this detector.
     *
     * Example: 'OBF' for ObfuscationDetector, 'BACK' for BackdoorDetector
     *
     * The full rule ID is typically constructed by appending a numeric suffix:
     * getRuleId() . '-001', getRuleId() . '-042', etc.
     *
     * @return string The rule ID prefix (typically 3–4 uppercase letters)
     */
    abstract public function getRuleId(): string;

    /**
     * Returns the list of supported file extensions including the leading dot.
     *
     * Example: ['.php', '.phtml']
     *
     * Return ['*'] to support all extensions regardless of type.
     *
     * Requirement 3.4: detectors declare which file types they support and are
     * skipped silently for unsupported types.
     *
     * @return string[]
     */
    abstract public function getSupportedExtensions(): array;

    /**
     * Core detection method — receives an AnalysisObject and returns an array
     * of Finding objects.
     *
     * Implementations MUST NOT throw exceptions; all errors should be caught
     * internally and either ignored or wrapped in a DetectorException if the
     * caller needs to be notified.
     *
     * Requirement 3.2: each Detector receives the shared AnalysisObject and
     * returns zero or more Findings.
     *
     * @return Finding[]
     */
    abstract public function detect(AnalysisObject $ao): array;

    /**
     * Returns true if this detector should run on the given AnalysisObject.
     *
     * Default implementation: returns true when getSupportedExtensions() === ['*'],
     * or when the file's lowercase extension is in getSupportedExtensions().
     *
     * Requirement 3.4: detectors are skipped silently for unsupported types.
     */
    public function isApplicable(AnalysisObject $ao): bool
    {
        $extensions = $this->getSupportedExtensions();

        if ($extensions === ['*']) {
            return true;
        }

        return \in_array(strtolower($ao->meta->extension), $extensions, true);
    }

    /**
     * Exception-safe wrapper around detect().
     *
     * Calls detect() and returns its result on success.
     * On any Throwable, logs to error_log and returns an empty array so the
     * scan can continue without crashing.
     *
     * Requirement 3.3: when a Detector fails, the scanner logs a warning and
     * continues running other Detectors on the same file.
     *
     * @return Finding[]
     */
    public function safeDetect(AnalysisObject $ao): array
    {
        try {
            return $this->detect($ao);
        } catch (\Throwable $e) {
            \error_log(\sprintf(
                '[WPMA] %s failed on %s: %s',
                $this->getName(),
                $ao->meta->filePath,
                $e->getMessage(),
            ));

            return [];
        }
    }

    // -------------------------------------------------------------------------
    // Protected helper methods for use by concrete detectors
    // -------------------------------------------------------------------------

    /**
     * Creates an EvidenceItem with the given line, snippet, and description.
     *
     * @param int    $line        The line number in the source file (1-based)
     * @param string $snippet     Code snippet showing the evidence (max 500 chars)
     * @param string $description Human-readable description of this evidence item
     */
    protected function makeEvidence(int $line, string $snippet, string $description): EvidenceItem
    {
        // Cap snippet at 500 characters as per EvidenceItem specification
        if (\strlen($snippet) > 500) {
            $snippet = \substr($snippet, 0, 497) . '...';
        }

        return new EvidenceItem(
            line: $line,
            snippet: $snippet,
            description: $description,
        );
    }

    /**
     * Creates a Finding from an associative array of parameters.
     *
     * This is a convenience wrapper around Finding::create() that detectors
     * can use to construct findings without directly calling the Finding factory.
     *
     * @param array<string, mixed> $params Associative array with Finding fields
     * @return Finding The constructed Finding instance
     */
    protected function makeFinding(array $params): Finding
    {
        return Finding::create($params);
    }

    /**
     * Extracts a snippet of source code centered around a specific line.
     *
     * Returns up to $context lines before and after the target line, joined
     * with newlines. The result is capped at 500 characters.
     *
     * @param string $source  The full source code
     * @param int    $line    The target line number (1-based)
     * @param int    $context Number of lines of context before/after (default: 2)
     * @return string The extracted snippet, capped at 500 characters
     */
    protected function snippet(string $source, int $line, int $context = 2): string
    {
        $lines = \explode("\n", $source);
        $totalLines = \count($lines);

        // Adjust to 0-based indexing
        $targetIndex = $line - 1;

        // Clamp target line to valid range
        if ($targetIndex < 0) {
            $targetIndex = 0;
        }
        if ($targetIndex >= $totalLines) {
            $targetIndex = $totalLines - 1;
        }

        // Calculate start and end indices
        $startIndex = \max(0, $targetIndex - $context);
        $endIndex = \min($totalLines - 1, $targetIndex + $context);

        // Extract the slice
        $snippetLines = \array_slice($lines, $startIndex, $endIndex - $startIndex + 1);
        $snippet = \implode("\n", $snippetLines);

        // Cap at 500 characters
        if (\strlen($snippet) > 500) {
            $snippet = \substr($snippet, 0, 497) . '...';
        }

        return $snippet;
    }
}
