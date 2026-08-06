<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * AnalysisObject — the central, immutable data structure produced by the analysis pipeline.
 *
 * The pipeline constructs exactly one AnalysisObject per file and passes it read-only to every
 * Detector. No Detector may modify this object; all detection results are returned as Finding
 * arrays rather than being written back here.
 *
 * The IOC extractor populates $iocs as the final pipeline step. During Phase 1 this array
 * will be empty until the IOCExtractor is implemented (task 2.4).
 */
readonly class AnalysisObject
{
    /**
     * @param FileMeta          $meta         Metadata about the source file.
     * @param string            $rawContent   The decoded source text of the file.
     * @param Token[]           $tokens       Flat PHP token stream produced by token_get_all().
     * @param FunctionCall[]    $functionCalls All function/method calls extracted from the
     *                                         token stream.
     * @param ExtractedString[] $strings      All string literals extracted from the token stream.
     * @param VariableRef[]     $variables    All variable references extracted from the token
     *                                         stream.
     * @param IncludeStatement[] $imports     All include/require statements extracted from the
     *                                         token stream.
     * @param VariableAssignment[] $assignments Simple variable assignment provenance extracted
     *                                         from the token stream.
     * @param array             $iocs         Array of IOC objects populated by the IOCExtractor.
     *                                         Elements are IOC instances (type declared when
     *                                         IOC model is added in task 1.5).
     * @param FileFeatures      $features     Higher-level features computed by the
     *                                         FeatureExtractor.
     * @param ParseError[]      $parseErrors  Non-fatal errors recorded during tokenisation or
     *                                         feature extraction. Detectors can still run when
     *                                         parse errors are present.
     */
    public function __construct(
        public FileMeta   $meta,
        public string     $rawContent,
        public array      $tokens,
        public array      $functionCalls,
        public array      $strings,
        public array      $variables,
        public array      $imports,
        public array      $assignments,
        public array      $iocs,
        public FileFeatures $features,
        public array      $parseErrors,
    ) {}

    // -------------------------------------------------------------------------
    // Helper methods — convenience queries used by multiple detectors
    // -------------------------------------------------------------------------

    /**
     * Returns true if any FunctionCall in this object has the given name,
     * using a case-insensitive comparison.
     *
     * Useful for detectors that need to check for dangerous function calls
     * without iterating the full list manually.
     *
     * @param string $name Function name to search for (e.g. 'eval', 'base64_decode').
     */
    public function hasFunctionCall(string $name): bool
    {
        $lowerName = strtolower($name);

        foreach ($this->functionCalls as $call) {
            if (strtolower($call->name) === $lowerName) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns true if any VariableRef in this object is a user-supplied superglobal
     * ($_POST, $_GET, $_REQUEST, $_COOKIE, $_SERVER, $_FILES).
     *
     * Detectors use this to distinguish static code from code that processes
     * attacker-controlled input — the primary escalation trigger for severity.
     */
    public function hasUserInput(): bool
    {
        foreach ($this->variables as $variable) {
            if ($variable->isUserInput) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns the list of encoded blob evidence strings from the file's features.
     *
     * Delegates to FileFeatures::$encodedBlobs for caller convenience; detectors
     * that only need the blob list do not need to reach into the features object.
     *
     * @return string[]
     */
    public function getEncodedBlobs(): array
    {
        return $this->features->encodedBlobs;
    }

    public function findAssignmentForVariable(string $variableName): ?VariableAssignment
    {
        return $this->findAssignmentForVariableBeforeLine($variableName, PHP_INT_MAX);
    }

    public function findAssignmentForVariableBeforeLine(string $variableName, int $line): ?VariableAssignment
    {
        for ($i = count($this->assignments) - 1; $i >= 0; $i--) {
            $assignment = $this->assignments[$i];
            if ($assignment->variableName === $variableName && $assignment->line <= $line) {
                return $this->withPropagatedAssignmentSignals($assignment, []);
            }
        }

        return null;
    }

    private function withPropagatedAssignmentSignals(VariableAssignment $assignment, array $visited): VariableAssignment
    {
        if (in_array($assignment->variableName . ':' . $assignment->line, $visited, true)) {
            return $assignment;
        }

        $visited[] = $assignment->variableName . ':' . $assignment->line;
        $functionNames = $assignment->functionNames;
        $usesUserInput = $assignment->usesUserInput;

        if (preg_match_all('/\$[a-zA-Z_][\w]*/', $assignment->expression, $matches)) {
            foreach (array_unique($matches[0]) as $referencedVariable) {
                if ($referencedVariable === $assignment->variableName) {
                    continue;
                }

                $source = $this->findAssignmentForVariableBeforeLineRaw($referencedVariable, $assignment->line - 1);
                if ($source === null) {
                    continue;
                }

                $source = $this->withPropagatedAssignmentSignals($source, $visited);
                $functionNames = array_values(array_unique(array_merge($functionNames, $source->functionNames)));
                $usesUserInput = $usesUserInput || $source->usesUserInput;
            }
        }

        return new VariableAssignment(
            variableName: $assignment->variableName,
            line: $assignment->line,
            expression: $assignment->expression,
            functionNames: $functionNames,
            usesUserInput: $usesUserInput,
        );
    }

    private function findAssignmentForVariableBeforeLineRaw(string $variableName, int $line): ?VariableAssignment
    {
        for ($i = count($this->assignments) - 1; $i >= 0; $i--) {
            $assignment = $this->assignments[$i];
            if ($assignment->variableName === $variableName && $assignment->line <= $line) {
                return $assignment;
            }
        }

        return null;
    }
}
