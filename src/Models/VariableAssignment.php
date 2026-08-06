<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * VariableAssignment — lightweight provenance for a simple variable assignment.
 */
readonly class VariableAssignment
{
    /**
     * @param string   $variableName
     * @param int      $line
     * @param string   $expression
     * @param string[] $functionNames
     */
    public function __construct(
        public string $variableName,
        public int $line,
        public string $expression,
        public array $functionNames = [],
        public bool $usesUserInput = false,
    ) {}
}
