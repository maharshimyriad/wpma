<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * ExtractedString — a string literal or interpolated string found in the source file.
 */
readonly class ExtractedString
{
    /**
     * @param string $value     The string value (decoded if it was a PHP escape sequence).
     * @param int    $line      The 1-based line number where the string appears.
     * @param bool   $isEncoded True when the string looks like a base64, hex, or similarly
     *                          encoded payload that may conceal a malicious payload.
     */
    public function __construct(
        public string $value,
        public int    $line,
        public bool   $isEncoded,
    ) {}
}
