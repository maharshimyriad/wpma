<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * ScanReport — the top-level immutable report produced after a completed scan.
 */
readonly class ScanReport
{
    /**
     * @param FileResult[]  $fileResults
     * @param IOC[]         $allIocs
     * @param Correlation[] $correlations
     * @param ScanWarning[] $warnings
     * @param array<string, array{status: string, version: string, modifiedFiles: array, method: string}> $pluginIntegrity
     */
    public function __construct(
        public string             $scanId,
        public string             $target,
        public \DateTimeImmutable $startedAt,
        public \DateTimeImmutable $completedAt,
        public float              $durationMs,
        public int                $filesScanned,
        public int                $filesSkipped,
        public array              $fileResults,
        public array              $allIocs,
        public array              $correlations,
        public array              $warnings,
        public float              $overallRiskScore,
        public string             $wpmaVersion = '2.0.0',
        public array              $pluginIntegrity = [],
    ) {}

    /**
     * Return all findings across all file results that meet the minimum severity.
     *
     * @return Finding[]
     */
    public function findingsBySeverity(Severity $min): array
    {
        $result = [];
        foreach ($this->fileResults as $fr) {
            foreach ($fr->findings as $finding) {
                if ($finding->severity->isAtLeast($min)) {
                    $result[] = $finding;
                }
            }
        }
        return $result;
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'scanId'           => $this->scanId,
            'target'           => $this->target,
            'startedAt'        => $this->startedAt->format(\DateTimeInterface::ATOM),
            'completedAt'      => $this->completedAt->format(\DateTimeInterface::ATOM),
            'durationMs'       => $this->durationMs,
            'filesScanned'     => $this->filesScanned,
            'filesSkipped'     => $this->filesSkipped,
            'overallRiskScore' => $this->overallRiskScore,
            'wpmaVersion'      => $this->wpmaVersion,
            'fileResults'      => array_map(static fn(FileResult $fr): array => $fr->toArray(), $this->fileResults),
            'allIocs'          => array_map(static fn(IOC $ioc): array => [
                'type'                 => $ioc->type->value,
                'value'                => $ioc->value,
                'filePath'             => $ioc->filePath,
                'line'                 => $ioc->line,
                'isPrivateIp'          => $ioc->isPrivateIp,
                'isKnownWpService'     => $ioc->isKnownWpService,
                'isConfirmedMalicious' => $ioc->isConfirmedMalicious,
                'tiCategory'           => $ioc->tiCategory,
                'tiReference'          => $ioc->tiReference,
            ], $this->allIocs),
            'correlations'     => array_map(static fn(Correlation $c): array => $c->toArray(), $this->correlations),
            'warnings'         => array_map(static fn(ScanWarning $w): array => [
                'message'     => $w->message,
                'filePath'    => $w->filePath,
                'warningType' => $w->warningType,
            ], $this->warnings),
            'pluginIntegrity'  => $this->pluginIntegrity,
        ];
    }
}
