<?php

declare(strict_types=1);

namespace Wpma\Detectors;

use Wpma\Models\AnalysisObject;
use Wpma\Models\Finding;

/**
 * DetectorInterface — contract that all detectors must satisfy.
 *
 * Type-hint against this interface rather than the abstract base class
 * when you need to accept or inject a detector without caring about the
 * helper methods on AbstractDetector.
 *
 * Requirements: 3.1 (Detector interface definition),
 *               3.2 (receives AnalysisObject, returns Findings),
 *               3.4 (declares supported file types).
 */
interface DetectorInterface
{
    /**
     * Returns a unique, human-readable name for this detector / rule set.
     *
     * Used in log output, warnings, and the `wpma rules` listing.
     *
     * Example: 'ObfuscationDetector', 'BackdoorDetector'
     */
    public function getName(): string;

    /**
     * Returns the semver-style version string for this detector.
     *
     * Example: '1.0.0', '2.3.1'
     */
    public function getVersion(): string;

    /**
     * Returns the list of supported file extensions including the leading dot.
     *
     * All values must be lowercase, e.g. ['.php', '.phtml'].
     * Return ['*'] to indicate that this detector applies to every file
     * regardless of extension.
     *
     * @return string[]
     */
    public function getSupportedExtensions(): array;

    /**
     * Core detection method — analyses the AnalysisObject and returns zero
     * or more Finding objects.
     *
     * MUST NOT throw; all errors must be handled internally.
     * MUST NOT perform I/O or modify the AnalysisObject.
     *
     * @return Finding[]
     */
    public function detect(AnalysisObject $ao): array;

    /**
     * Returns true when this detector should run on the given file.
     *
     * Implementations check the file's extension against
     * getSupportedExtensions(), or return true unconditionally when
     * getSupportedExtensions() returns ['*'].
     */
    public function isApplicable(AnalysisObject $ao): bool;

    /**
     * Exception-safe wrapper around detect().
     *
     * Calls detect() and returns its result on success.
     * On any Throwable, logs to error_log and returns an empty array so the
     * scan can continue without crashing.
     *
     * @return Finding[]
     */
    public function safeDetect(AnalysisObject $ao): array;
}
