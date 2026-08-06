<?php

declare(strict_types=1);

namespace Wpma\WP;

/**
 * PluginIntegrity — result of a WordPress.org checksum verification for one plugin.
 *
 * Status values:
 *   VERIFIED    — all official files match; no unexpected files found
 *   MODIFIED    — at least one official file has been changed, OR extra files exist
 *   UNAVAILABLE           — plugin is not on WordPress.org (premium/custom/private)
 *   ERROR               — API unreachable or check failed (treat same as UNAVAILABLE)
 *   CHECKSUM_UNAVAILABLE — WordPress.org checksum API unreachable (network/5xx)
 */
class PluginIntegrity
{
    public const VERIFIED    = 'verified';
    public const MODIFIED    = 'modified';
    public const UNAVAILABLE = 'unavailable';
    public const ERROR               = 'error';
    public const CHECKSUM_UNAVAILABLE = 'checksum_unavailable';

    public readonly string $status;
    public readonly string $slug;
    public readonly string $version;

    /** Official files whose local sha256 differs from the API sha256 */
    public readonly array  $modifiedFiles;

    /** Local files that have no entry in the official manifest */
    public readonly array  $unexpectedFiles;

    /** Official files that are not present on disk */
    public readonly array  $missingFiles;

    public readonly string $method;

    /** Number of files in the official manifest */
    public readonly int $officialCount;

    /** Number of files found locally */
    public readonly int $localCount;

    /** Number of files that match exactly (sha256 == official) */
    public readonly int $okCount;

    /** Official local files that were successfully verified against checksums */
    public readonly array $verifiedFiles;

    public function __construct(
        string $status,
        string $slug,
        string $version         = '',
        array  $modifiedFiles   = [],
        array  $unexpectedFiles = [],
        array  $missingFiles    = [],
        string $method          = 'unavailable',
        int    $officialCount   = 0,
        int    $localCount      = 0,
        int    $okCount         = 0,
        array  $verifiedFiles   = [],
    ) {
        $this->status          = $status;
        $this->slug            = $slug;
        $this->version         = $version;
        $this->modifiedFiles   = $modifiedFiles;
        $this->unexpectedFiles = $unexpectedFiles;
        $this->missingFiles    = $missingFiles;
        $this->method          = $method;
        $this->officialCount   = $officialCount;
        $this->localCount      = $localCount;
        $this->okCount         = $okCount;
        $this->verifiedFiles   = $verifiedFiles;
    }

    public function isVerified(): bool    { return $this->status === self::VERIFIED; }
    public function isModified(): bool    { return $this->status === self::MODIFIED; }
    public function isUnavailable(): bool { return \in_array($this->status, [self::UNAVAILABLE, self::ERROR, self::CHECKSUM_UNAVAILABLE], true); }

    /**
     * Build a human-readable debug summary, e.g.:
     *   Plugin: yith-woocommerce-social-login  Version: 1.2.5
     *   Official files: 501  Local files: 475  OK: 471  MODIFIED: 0  MISSING: 30  EXTRA: 4
     */
    public function debugSummary(): string
    {
        if ($this->status === self::CHECKSUM_UNAVAILABLE) {
            return sprintf("Plugin: %s  Integrity: CHECKSUM_UNAVAILABLE (WordPress.org checksum API unreachable)", $this->slug);
        }
        if ($this->isUnavailable()) {
            return sprintf("Plugin: %s  Integrity: UNAVAILABLE (not on WordPress.org)", $this->slug);
        }
        return sprintf(
            "Plugin: %s  Version: %s\nOfficial files: %d  Local files: %d  OK: %d  MODIFIED: %d  MISSING: %d  EXTRA: %d",
            $this->slug,
            $this->version,
            $this->officialCount,
            $this->localCount,
            $this->okCount,
            count($this->modifiedFiles),
            count($this->missingFiles),
            count($this->unexpectedFiles),
        );
    }

    /**
     * Confidence multiplier for malware findings in this plugin.
     * Verified:   reduce confidence on common WP patterns.
     * Modified:   increase confidence on suspicious findings.
     * Unavailable: no adjustment.
     */
    public function confidenceMultiplier(): float
    {
        return match ($this->status) {
            self::VERIFIED    => 0.6,
            self::MODIFIED    => 1.4,
            default           => 1.0,
        };
    }
}
