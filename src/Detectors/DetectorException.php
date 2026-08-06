<?php

declare(strict_types=1);

namespace Wpma\Detectors;

/**
 * DetectorException — thrown when a detector encounters an unrecoverable internal error.
 *
 * Detectors should only throw this when they have exhausted all internal fallback strategies
 * and cannot produce a meaningful result. The ScanOrchestrator catches DetectorException
 * (along with any other \Throwable) and records a ScanWarning so the scan continues.
 */
class DetectorException extends \RuntimeException
{
}
