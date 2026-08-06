<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * ScanWarning — an immutable value object representing a non-fatal warning
 * encountered during scanning.
 *
 * Valid $warningType values:
 *   'skipped_size'        — file was skipped due to size limit
 *   'skipped_permission'  — file was skipped due to permission error
 *   'skipped_symlink'     — file was skipped because it is a symlink
 *   'detector_error'      — a detector threw an error while processing the file
 *   'parse_error'         — PHP parsing of the file failed
 *   'rule_load_error'     — a rule could not be loaded
 */
readonly class ScanWarning
{
    public function __construct(
        public string $message,
        public string $filePath,
        public string $warningType,
    ) {}
}
