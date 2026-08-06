<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * Finding — an immutable value object representing a single detected threat.
 *
 * Rule ID format: [A-Z]{3,}-[0-9]{3,}  e.g. OBF-001, BACK-042
 * Title:          max 80 characters
 * Remediation:    required (non-empty) when severity >= HIGH
 */
readonly class Finding
{
    /**
     * @param EvidenceItem[]    $evidence
     * @param IOC[]             $iocs
     * @param MITRETechnique[]  $mitreTechniques
     * @param string[]          $tags
     */
    public function __construct(
        public string            $ruleId,
        public string            $title,
        public string            $filePath,
        public int               $line,
        public Severity          $severity,
        public Confidence        $confidence,
        public DetectionCategory $category,
        public string            $description,
        public string            $explanation,
        public string            $remediation,
        public array             $evidence,
        public array             $iocs,
        public array             $mitreTechniques,
        public array             $tags,
    ) {}

    /**
     * Factory method: build a Finding from a plain associative array.
     *
     * Required keys: ruleId, title, filePath, line, severity, confidence,
     *                category, description, explanation.
     *
     * Optional keys: remediation (default ''), evidence, iocs,
     *                mitreTechniques, tags.
     *
     * @param array<string, mixed> $params
     */
    public static function create(array $params): self
    {
        return new self(
            ruleId:          (string) ($params['ruleId'] ?? ''),
            title:           (string) ($params['title'] ?? ''),
            filePath:        (string) ($params['filePath'] ?? ''),
            line:            (int)    ($params['line'] ?? 0),
            severity:        $params['severity'] instanceof Severity
                                 ? $params['severity']
                                 : Severity::from((string) ($params['severity'] ?? 'informational')),
            confidence:      $params['confidence'] instanceof Confidence
                                 ? $params['confidence']
                                 : Confidence::from((string) ($params['confidence'] ?? 'low')),
            category:        $params['category'] instanceof DetectionCategory
                                 ? $params['category']
                                 : DetectionCategory::from((string) ($params['category'] ?? 'custom')),
            description:     (string) ($params['description'] ?? ''),
            explanation:     (string) ($params['explanation'] ?? ''),
            remediation:     (string) ($params['remediation'] ?? ''),
            evidence:        (array)  ($params['evidence'] ?? []),
            iocs:            (array)  ($params['iocs'] ?? []),
            mitreTechniques: (array)  ($params['mitreTechniques'] ?? []),
            tags:            (array)  ($params['tags'] ?? []),
        );
    }

    /**
     * Serialise the Finding to a plain associative array (e.g. for JSON output).
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'ruleId'          => $this->ruleId,
            'title'           => $this->title,
            'filePath'        => $this->filePath,
            'line'            => $this->line,
            'severity'        => $this->severity->value,
            'confidence'      => $this->confidence->value,
            'category'        => $this->category->value,
            'description'     => $this->description,
            'explanation'     => $this->explanation,
            'remediation'     => $this->remediation,
            'evidence'        => array_map(
                static fn(EvidenceItem $e): array => [
                    'line'        => $e->line,
                    'snippet'     => $e->snippet,
                    'description' => $e->description,
                ],
                $this->evidence,
            ),
            'iocs'            => array_map(
                static fn(IOC $ioc): array => [
                    'type'                => $ioc->type->value,
                    'value'               => $ioc->value,
                    'filePath'            => $ioc->filePath,
                    'line'                => $ioc->line,
                    'isPrivateIp'         => $ioc->isPrivateIp,
                    'isKnownWpService'    => $ioc->isKnownWpService,
                    'isConfirmedMalicious' => $ioc->isConfirmedMalicious,
                    'tiCategory'          => $ioc->tiCategory,
                    'tiReference'         => $ioc->tiReference,
                ],
                $this->iocs,
            ),
            'mitreTechniques' => array_map(
                static fn(MITRETechnique $t): array => [
                    'id'   => $t->id,
                    'name' => $t->name,
                    'url'  => $t->url,
                ],
                $this->mitreTechniques,
            ),
            'tags'            => $this->tags,
        ];
    }
}
