<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * ParseError — a non-fatal error recorded during PHP tokenisation or extraction.
 *
 * Parse errors do not abort the scan. They are collected on the AnalysisObject
 * so that detectors can still perform pattern-based analysis on the raw content
 * and callers can surface the issues in the scan report warnings.
 */
readonly class ParseError
{
    /**
     * @param string $message A human-readable description of what went wrong.
     * @param int    $line    The 1-based line number where the error occurred,
     *                        or 0 if the error is not associated with a specific line.
     * @param string $context A short snippet of source code surrounding the error,
     *                        used for display in reports.
     */
    public function __construct(
        public string $message,
        public int    $line,
        public string $context,
    ) {}
}
