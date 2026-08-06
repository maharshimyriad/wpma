<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * WPContext — the WordPress structural context a scanned file belongs to.
 */
enum WPContext: string
{
    case CORE      = 'core';
    case PLUGIN    = 'plugin';
    case THEME     = 'theme';
    case UPLOAD    = 'upload';
    case MU_PLUGIN = 'mu_plugin';
    case DROP_IN   = 'drop_in';
    case ARBITRARY = 'arbitrary';

    /**
     * Returns true for contexts that are inherently higher risk
     * and should trigger severity escalation.
     *
     * UPLOAD — PHP files in wp-content/uploads/ should not exist.
     * MU_PLUGIN — Must-use plugins load automatically without activation.
     */
    public function isHighRisk(): bool
    {
        return match ($this) {
            self::UPLOAD    => true,
            self::MU_PLUGIN => true,
            default         => false,
        };
    }
}
