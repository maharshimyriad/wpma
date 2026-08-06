<?php

declare(strict_types=1);

namespace Wpma\Cli;

readonly class DetectedScanTarget
{
    public function __construct(
        public string $requestedPath,
        public ?string $resolvedPath,
        public ScanTargetType $targetType,
        public string $scanMode,
        public ?string $componentName = null,
        public ?string $validationError = null,
        public bool $usedExplicitOverride = false,
    ) {}

    public function isValid(): bool
    {
        return $this->resolvedPath !== null && $this->validationError === null;
    }
}
