<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * EvidenceItem — a single piece of code evidence supporting a Finding.
 *
 * The snippet is capped at 500 characters to keep reports readable.
 */
readonly class EvidenceItem
{
    public function __construct(
        public int    $line,
        public string $snippet,
        public string $description,
    ) {}
}
