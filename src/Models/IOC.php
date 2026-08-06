<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * IOC — an Indicator of Compromise extracted from a scanned file.
 */
readonly class IOC
{
    public function __construct(
        public IOCType  $type,
        public string   $value,
        public string   $filePath,
        public int      $line,
        public bool     $isPrivateIp         = false,
        public bool     $isKnownWpService    = false,
        public bool     $isConfirmedMalicious = false,
        public ?string  $tiCategory          = null,
        public ?string  $tiReference         = null,
    ) {}
}
