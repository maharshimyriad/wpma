<?php

declare(strict_types=1);

namespace Wpma\Pipeline;

use Wpma\Models\ExtractedString;
use Wpma\Models\FunctionCall;
use Wpma\Models\IncludeStatement;
use Wpma\Models\VariableAssignment;
use Wpma\Models\VariableRef;

/**
 * TokenExtractorResult — the value object returned by TokenExtractor::extract().
 *
 * Holds all structured data items pulled from the flat PHP token stream.
 */
readonly class TokenExtractorResult
{
    /**
     * @param FunctionCall[]     $functionCalls  Function and dynamic-dispatch invocations.
     * @param ExtractedString[]  $strings        String literals found in the source.
     * @param VariableRef[]       $variables       Variable references found in the source.
     * @param IncludeStatement[]  $imports         include/require statements found in the source.
     * @param VariableAssignment[] $assignments    Simple variable assignment provenance.
     */
    public function __construct(
        public array $functionCalls,
        public array $strings,
        public array $variables,
        public array $imports,
        public array $assignments = [],
    ) {}
}
