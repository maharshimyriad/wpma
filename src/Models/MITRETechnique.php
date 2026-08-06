<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * MITRETechnique — a MITRE ATT&CK technique associated with a Finding.
 */
readonly class MITRETechnique
{
    /**
     * Built-in ATT&CK technique mapping: id → [name, url].
     *
     * @var array<string, array{0: string, 1: string}>
     */
    private const MAPPING = [
        'T1059.004' => [
            'Command and Scripting Interpreter: Unix Shell',
            'https://attack.mitre.org/techniques/T1059/004/',
        ],
        'T1027'     => [
            'Obfuscated Files or Information',
            'https://attack.mitre.org/techniques/T1027/',
        ],
        'T1071.001' => [
            'Application Layer Protocol: Web Protocols',
            'https://attack.mitre.org/techniques/T1071/001/',
        ],
        'T1105'     => [
            'Ingress Tool Transfer',
            'https://attack.mitre.org/techniques/T1105/',
        ],
        'T1136'     => [
            'Create Account',
            'https://attack.mitre.org/techniques/T1136/',
        ],
        'T1505.003' => [
            'Server Software Component: Web Shell',
            'https://attack.mitre.org/techniques/T1505/003/',
        ],
        'T1546'     => [
            'Event Triggered Execution',
            'https://attack.mitre.org/techniques/T1546/',
        ],
        'T1556'     => [
            'Modify Authentication Process',
            'https://attack.mitre.org/techniques/T1556/',
        ],
        'T1020'     => [
            'Automated Exfiltration',
            'https://attack.mitre.org/techniques/T1020/',
        ],
        'T1036'     => [
            'Masquerading',
            'https://attack.mitre.org/techniques/T1036/',
        ],
        'T1190'     => [
            'Exploit Public-Facing Application',
            'https://attack.mitre.org/techniques/T1190/',
        ],
        'T1565'     => [
            'Data Manipulation',
            'https://attack.mitre.org/techniques/T1565/',
        ],
    ];

    public function __construct(
        public string $id,
        public string $name,
        public string $url,
    ) {}

    /**
     * Look up a technique by its ATT&CK ID.
     *
     * Returns null when the ID is not in the built-in mapping.
     */
    public static function fromId(string $id): ?self
    {
        if (!isset(self::MAPPING[$id])) {
            return null;
        }

        [$name, $url] = self::MAPPING[$id];

        return new self($id, $name, $url);
    }
}
