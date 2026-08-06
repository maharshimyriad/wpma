<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * Severity — five-level risk classification for Findings.
 */
enum Severity: string
{
    case INFORMATIONAL = 'informational';
    case LOW           = 'low';
    case MEDIUM        = 'medium';
    case HIGH          = 'high';
    case CRITICAL      = 'critical';

    /**
     * Numeric weight used for ordering and comparison (0–4).
     */
    public function weight(): int
    {
        return match ($this) {
            self::INFORMATIONAL => 0,
            self::LOW           => 1,
            self::MEDIUM        => 2,
            self::HIGH          => 3,
            self::CRITICAL      => 4,
        };
    }

    /**
     * Returns true if this severity is at least as severe as $other.
     */
    public function isAtLeast(Severity $other): bool
    {
        return $this->weight() >= $other->weight();
    }

    /**
     * Uppercase display label.
     */
    public function label(): string
    {
        return strtoupper($this->name);
    }
}
