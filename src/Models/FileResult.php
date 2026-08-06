<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * FileResult — immutable result for a single scanned file.
 */
readonly class FileResult
{
    /**
     * @param Finding[] $findings
     * @param IOC[]     $iocs
     */
    public function __construct(
        public string    $filePath,
        public string    $relativePath,
        public array     $findings,
        public array     $iocs,
        public float     $riskScore,
        public ?WPContext $wpContext,
        public float     $scanTimeMs,
    ) {}

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'filePath'      => $this->filePath,
            'relativePath'  => $this->relativePath,
            'riskScore'     => $this->riskScore,
            'scanTimeMs'    => $this->scanTimeMs,
            'wpContext'     => $this->wpContext?->value,
            'findingsCount' => count($this->findings),
            'iocsCount'     => count($this->iocs),
            'findings'      => array_map(static fn(Finding $f): array => $f->toArray(), $this->findings),
            'iocs'          => array_map(static fn(IOC $ioc): array => [
                'type'                 => $ioc->type->value,
                'value'                => $ioc->value,
                'filePath'             => $ioc->filePath,
                'line'                 => $ioc->line,
                'isPrivateIp'          => $ioc->isPrivateIp,
                'isKnownWpService'     => $ioc->isKnownWpService,
                'isConfirmedMalicious' => $ioc->isConfirmedMalicious,
                'tiCategory'           => $ioc->tiCategory,
                'tiReference'          => $ioc->tiReference,
            ], $this->iocs),
        ];
    }
}
