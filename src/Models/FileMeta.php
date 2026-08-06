<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * FileMeta — immutable metadata about a scanned file.
 *
 * Populated by the pipeline runner before any extraction or detection takes place.
 */
readonly class FileMeta
{
    /**
     * @param string        $filePath     Absolute filesystem path to the file.
     * @param string        $relativePath Path relative to the scan root, used in reports.
     * @param int           $fileSize     File size in bytes.
     * @param string        $extension    Lowercase file extension including the leading dot
     *                                   (e.g. '.php', '.phtml'). Empty string if no extension.
     * @param string        $encoding     Detected character encoding (e.g. 'UTF-8', 'ISO-8859-1').
     * @param int           $lineCount    Total number of lines in the file.
     * @param float         $scanTimeMs  Time in milliseconds taken to process this file
     *                                   through the pipeline.
     * @param WPContext|null $wpContext   The WordPress structural context this file belongs to,
     *                                   or null when scanning outside a WP installation.
     */
    public function __construct(
        public string      $filePath,
        public string      $relativePath,
        public int         $fileSize,
        public string      $extension,
        public string      $encoding,
        public int         $lineCount,
        public float       $scanTimeMs,
        public ?WPContext  $wpContext    = null,
    ) {}
}
