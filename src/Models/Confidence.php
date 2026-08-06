<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * Confidence — qualitative score expressing how likely a Finding is a true positive.
 */
enum Confidence: string
{
    case LOW    = 'low';
    case MEDIUM = 'medium';
    case HIGH   = 'high';

    /**
     * Numeric weight used for scoring (0–2).
     */
    public function weight(): int
    {
        return match ($this) {
            self::LOW    => 0,
            self::MEDIUM => 1,
            self::HIGH   => 2,
        };
    }
}
