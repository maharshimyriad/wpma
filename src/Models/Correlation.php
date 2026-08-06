<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * Correlation — an immutable value object representing a threat correlation
 * across multiple files or findings.
 */
readonly class Correlation
{
    /**
     * @param CorrelationType $type             The type of correlation
     * @param string          $title            Short descriptive title
     * @param string          $description      Detailed description of the correlation
     * @param array           $involvedFiles    File paths involved in this correlation
     * @param array           $involvedFindings Array of Finding ruleIds involved
     * @param float           $escalatedScore   Escalated risk score for this correlation
     */
    public function __construct(
        public CorrelationType $type,
        public string          $title,
        public string          $description,
        public array           $involvedFiles,
        public array           $involvedFindings,
        public float           $escalatedScore,
    ) {}

    /**
     * Serialise to a plain associative array (e.g. for JSON output).
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'type'             => $this->type->value,
            'title'            => $this->title,
            'description'      => $this->description,
            'involvedFiles'    => $this->involvedFiles,
            'involvedFindings' => $this->involvedFindings,
            'escalatedScore'   => $this->escalatedScore,
        ];
    }
}
