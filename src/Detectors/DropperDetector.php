<?php

declare(strict_types=1);

namespace Wpma\Detectors;

use Wpma\Models\AnalysisObject;
use Wpma\Models\Confidence;
use Wpma\Models\DetectionCategory;
use Wpma\Models\Finding;
use Wpma\Models\FunctionCall;
use Wpma\Models\IOC;
use Wpma\Models\IOCType;
use Wpma\Models\Severity;
use Wpma\Models\Token;
use Wpma\Pipeline\PhpTokenizer;

/**
 * DropperDetector — detects dropper and downloader patterns in PHP files.
 *
 * A dropper/downloader is malware that fetches a secondary payload from a
 * remote server and installs it on the local filesystem. This is the exact
 * pattern found in the RevSlider c/s archive attack:
 *   1. Contact a remote .ru server via cURL
 *   2. Write the downloaded PHP code to shop.php
 *   3. The written file is the persistent backdoor
 *
 * Rules (applied in priority order — a higher rule suppresses lower ones
 * for the same file to avoid redundant findings):
 *
 *   DROP-001  Remote payload dropper correlation
 *             (remote/network fetch + local file write + corroborating signals)
 *   DROP-002  Decoded/deobfuscated content written to file (decode-write dropper)
 *   DROP-003  File written to an explicitly server-executable path (e.g. "shop.php")
 *   DROP-004  move_uploaded_file() to an executable-extension destination
 *             (checked independently of the above three rules)
 *
 * Severity escalation:
 *   - Writing to a *.php / *.phar / *.phtml path → always CRITICAL
 *   - obfuscationScore > 0.35 → escalates to CRITICAL
 *   - Inherently-remote functions (curl_exec, fsockopen) → higher base confidence
 */
class DropperDetector extends AbstractDetector
{
    public function getName(): string    { return 'DropperDetector'; }
    public function getVersion(): string { return '1.0.0'; }
    public function getRuleId(): string  { return 'DROP'; }

    public function getSupportedExtensions(): array
    {
        return ['.php', '.phtml', '.php5', '.php7', '.phar'];
    }

    /**
     * Functions that are inherently remote.
     * Used only as a coarse pre-filter to decide whether a file is worth
     * inspecting for DROP-001 at all. The actual DROP-001 finding additionally
     * requires proving that a specific write call's content genuinely derives
     * from a remote fetch (see buildRemotePayloadDropperCorrelation()).
     */
    private const INHERENTLY_REMOTE = [
        'curl_exec', 'curl_multi_exec',
        'fsockopen', 'pfsockopen',
        'stream_socket_client',
    ];

    /**
     * Functions that can be local or remote.
     * Classified as remote only when the first argument is a literal URL, or
     * a variable whose own provenance resolves (directly or transitively) to
     * a literal URL. A bare variable with no such provenance is NOT assumed
     * to be remote — fopen()/file_get_contents() are routinely used on local
     * paths held in variables.
     */
    private const POSSIBLY_REMOTE = ['file_get_contents', 'fopen'];

    /** Bound on provenance-chain recursion depth when resolving remote-fetch origin. */
    private const REMOTE_FETCH_MAX_DEPTH = 4;

    /** Functions that write content to the filesystem. */
    private const WRITE_FUNCS = ['file_put_contents', 'fwrite', 'fputs'];

    /** Decode / deobfuscation functions. */
    private const DECODE_FUNCS = [
        'base64_decode', 'str_rot13',
        'gzinflate', 'gzdecode', 'gzuncompress',
        'hex2bin', 'rawurldecode',
    ];

    /** Server-side executable extensions. */
    private const EXECUTABLE_EXTS = [
        'php', 'phtml', 'phar', 'php5', 'php7', 'pht', 'shtml',
    ];

    public function detect(AnalysisObject $ao): array
    {
        $findings = [];
        $file     = $ao->meta->filePath;

        // ── Single pass: bucket all relevant function calls ───────────────────
        $remoteCalls = [];
        $writeCalls  = [];
        $uploadCalls = [];

        foreach ($ao->functionCalls as $call) {
            $lower = strtolower($call->name);

            if ($this->isRemoteNetworkCall($call, $ao)) {
                $remoteCalls[] = $call;
            } elseif (in_array($lower, self::WRITE_FUNCS, true)) {
                $writeCalls[] = $call;
            } elseif ($lower === 'move_uploaded_file') {
                $uploadCalls[] = $call;
            }
        }

        // ── DROP-001: Remote payload dropper correlation ───────────────
        if (!empty($remoteCalls) && !empty($writeCalls)) {
            $correlation = $this->buildRemotePayloadDropperCorrelation($ao, $writeCalls);
            if ($correlation !== null) {
                $findings[] = $correlation;
            }

            // DROP-001 supersedes DROP-002 and DROP-003 for the same file.
            // DROP-004 (uploaded file) is always checked independently below.

        } elseif (!empty($writeCalls)) {
            // ── DROP-003: Suspicious executable payload write ─────────────────
            $executablePayloadWrite = $this->buildSuspiciousExecutablePayloadWriteFinding($ao, $writeCalls);
            if ($executablePayloadWrite !== null) {
                $findings[] = $executablePayloadWrite;
            }

            // ── DROP-005: Suspicious wp-config.php modification ───────────────
            $wpConfigWrite = $this->buildSuspiciousWpConfigModificationFinding($ao, $writeCalls);
            if ($wpConfigWrite !== null) {
                $findings[] = $wpConfigWrite;
            }

            // ── DROP-006: Suspicious .htaccess modification ───────────────────
            $htaccessWrite = $this->buildSuspiciousHtaccessModificationFinding($ao, $writeCalls);
            if ($htaccessWrite !== null) {
                $findings[] = $htaccessWrite;
            }
        }

        if (!empty($writeCalls)) {
            // ── DROP-002: Decoded content actually written to file ────────────
            $decoderWriterFinding = $this->buildDecoderWriterFinding($ao, $writeCalls);
            if ($decoderWriterFinding !== null) {
                $findings[] = $decoderWriterFinding;
            }
        }

        // ── DROP-004: move_uploaded_file to executable destination ────────────
        // Checked independently — a file can trigger both DROP-001 and DROP-004.
        foreach ($uploadCalls as $call) {
            $dest = trim($call->args[1] ?? '');
            if ($dest !== '' && $this->isStaticallyExecutablePath($dest)) {
                $argDisplay = implode(', ', array_slice($call->args, 0, 2));
                $findings[] = Finding::create([
                    'ruleId'      => 'DROP-004',
                    'title'       => 'Uploaded file moved to server-executable path',
                    'filePath'    => $file,
                    'line'        => $call->line,
                    'severity'    => Severity::HIGH,
                    'confidence'  => Confidence::HIGH,
                    'category'    => DetectionCategory::PERSISTENCE,
                    'description' => sprintf(
                        'move_uploaded_file() moves an uploaded file to a path with a '
                        . 'server-executable extension: %s',
                        $dest,
                    ),
                    'explanation' => 'Legitimate WordPress file uploads go to wp-content/uploads/. '
                        . 'Moving an uploaded file to a path with a .php (or similar) extension is '
                        . 'the standard technique for installing a webshell through a compromised '
                        . 'or deliberately vulnerable file upload handler.',
                    'remediation' => 'Audit the upload handler logic. Check for recently uploaded '
                        . 'PHP files in unexpected directories. Restrict allowed upload extensions '
                        . 'in the application.',
                    'evidence'    => [
                        $this->makeEvidence(
                            $call->line,
                            $this->snippet($ao->rawContent, $call->line),
                            'move_uploaded_file(' . $argDisplay . ')',
                        ),
                    ],
                    'tags' => ['dropper', 'upload', 'webshell-upload', 'persistence'],
                ]);
            }
        }

        return $findings;
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /**
     * True when $call makes a remote network connection.
     *
     * - INHERENTLY_REMOTE functions always qualify (coarse pre-filter only).
     * - POSSIBLY_REMOTE functions qualify only when their first argument is a
     *   literal URL, or a variable whose own provenance resolves to one.
     * - Local paths, and variables with no provenance establishing a remote
     *   origin, do NOT qualify.
     */
    private function isRemoteNetworkCall(FunctionCall $call, AnalysisObject $ao): bool
    {
        $lower = strtolower($call->name);

        if (in_array($lower, self::INHERENTLY_REMOTE, true)) {
            return true;
        }

        if (in_array($lower, self::POSSIBLY_REMOTE, true)) {
            $first = trim($call->args[0] ?? '');
            return $this->argumentLooksLikeRemoteUrl($ao, $first, 0);
        }

        return false;
    }

    /**
     * True when $arg is a literal http(s) URL, or a bare variable whose own
     * provenance (directly or via a bounded transitive chain) resolves to a
     * literal http(s) URL. Unresolvable variables are NOT assumed remote.
     */
    private function argumentLooksLikeRemoteUrl(AnalysisObject $ao, string $arg, int $depth): bool
    {
        $arg = trim($arg);
        if ($arg === '' || $depth > self::REMOTE_FETCH_MAX_DEPTH) {
            return false;
        }

        if (preg_match('/https?:\/\//i', $arg) === 1) {
            return true;
        }

        if (preg_match('/^\$[a-zA-Z_][\w]*$/', $arg) === 1) {
            $assignment = $ao->findAssignmentForVariable($arg);
            if ($assignment !== null) {
                return $this->argumentLooksLikeRemoteUrl($ao, $assignment->expression, $depth + 1);
            }
        }

        return false;
    }

    /**
     * Build a DROP-001 finding only when a specific write call's OWN content
     * argument can be shown — via direct embedding or existing provenance
     * chains — to genuinely derive from a remote/network fetch. Remote and
     * write functions merely coexisting in the file is NOT sufficient, and
     * unrelated file-level signals (obfuscation, user input elsewhere,
     * unrelated IOCs, etc.) are never used as a substitute for that
     * remote-source → write-content correlation; they may only escalate
     * severity/confidence once the correlation is already established.
     */
    private function buildRemotePayloadDropperCorrelation(
        AnalysisObject $ao,
        array $writeCalls,
    ): ?Finding {
        $currentFile = (string) ($ao->meta->filePath ?? '');

        foreach ($writeCalls as $writeCall) {
            $contentArg = trim($writeCall->args[1] ?? '');
            if ($contentArg === '') {
                continue;
            }

            $remoteFetch = $this->resolveRemoteFetchForContent($ao, $contentArg, $writeCall->line);
            if ($remoteFetch === null) {
                continue; // cannot establish that this write's content derives from a remote fetch
            }

            $writesExe = $this->isStaticallyExecutablePath($writeCall->args[0] ?? '');

            $signals  = [$remoteFetch['reason']];
            $evidence = [
                $this->makeEvidence(
                    $remoteFetch['line'],
                    $this->snippet($ao->rawContent, $remoteFetch['line']),
                    'Remote-derived content: ' . $remoteFetch['reason'],
                ),
                $this->makeEvidence(
                    $writeCall->line,
                    $this->snippet($ao->rawContent, $writeCall->line),
                    'Local file write: ' . $writeCall->name . '()',
                ),
            ];

            $hasExecution = $ao->hasFunctionCall('eval') || $ao->hasFunctionCall('assert');
            $hasDangerousInput = $ao->hasUserInput();
            $hasDynamicDispatch = !empty($ao->features->dynamicDispatchCalls);
            $hasEncodedPayload = !empty($ao->features->encodedBlobs);
            $hasElevatedObfuscation = $ao->features->obfuscationScore >= 0.35;

            if ($writesExe) {
                $signals[] = 'writes fetched content to a server-executable path';
                $evidence[] = $this->makeEvidence(
                    $writeCall->line,
                    $this->snippet($ao->rawContent, $writeCall->line),
                    'Executable write destination: ' . $this->describeWriteDestination($writeCall),
                );
            }

            if ($hasExecution) {
                $signals[] = 'contains direct code-execution capability';
            }

            if ($hasDynamicDispatch) {
                $signals[] = 'uses dynamic dispatch';
                $dynamic = $ao->features->dynamicDispatchCalls[0];
                [$name, $line] = $this->splitFeatureCallEvidence($dynamic);
                if ($line !== null) {
                    $evidence[] = $this->makeEvidence(
                        $line,
                        $this->snippet($ao->rawContent, $line),
                        'Dynamic dispatch: ' . $name . '()',
                    );
                }
            }

            if ($hasEncodedPayload) {
                $signals[] = 'contains encoded payload material';
            }

            if ($hasElevatedObfuscation) {
                $signals[] = sprintf('has elevated obfuscation score (%.2f)', $ao->features->obfuscationScore);
            }

            if ($hasDangerousInput) {
                $signals[] = 'processes attacker-controlled input';
            }

            $payloadIocs = $this->extractSuspiciousPayloadIocs($ao->iocs, $currentFile);
            if (!empty($payloadIocs)) {
                $signals[] = 'contains remote payload/network IOCs';
            }

            $severity = ($writesExe || $hasExecution || $hasElevatedObfuscation)
                ? Severity::CRITICAL
                : Severity::HIGH;

            $description = sprintf(
                'This file writes content to the filesystem (%s()) that genuinely derives from a remote/network fetch (%s).',
                $writeCall->name,
                $remoteFetch['reason'],
            );

            $explanation = 'A local file write whose content is proven — via direct data flow or existing '
                . 'assignment provenance — to derive from a remote/network fetch is the core pattern of a '
                . 'PHP dropper: the attacker hosts a secondary payload remotely, and this file downloads and '
                . 'installs it locally.';

            if (count($signals) > 1) {
                $explanation .= ' Additional correlated signals: ' . implode('; ', $signals) . '.';
            }

            return Finding::create([
                'ruleId'      => 'DROP-001',
                'title'       => sprintf('Remote payload dropper: remote-fetched content written via %s()', $writeCall->name),
                'filePath'    => $currentFile,
                'line'        => $remoteFetch['line'],
                'severity'    => $severity,
                'confidence'  => ($writesExe || count($signals) >= 2) ? Confidence::HIGH : Confidence::MEDIUM,
                'category'    => DetectionCategory::PERSISTENCE,
                'description' => $description,
                'explanation' => $explanation,
                'remediation' => 'Determine whether the remote source, written payload, and any execution or obfuscation '
                    . 'logic are intentional and authorised. If unexpected, remove this file and any dropped payloads, '
                    . 'then review outbound PHP connections and recently created executable files.',
                'evidence'    => $evidence,
                'iocs'        => $payloadIocs,
                'tags'        => ['dropper', 'downloader', 'remote-fetch', 'file-write', 'behavior-correlation', 'persistence'],
            ]);
        }

        return null;
    }

    /**
     * Resolve whether a write call's content argument genuinely derives from
     * a remote/network fetch, either directly embedded in the content
     * expression or via the existing variable-assignment provenance chain.
     *
     * @return array{reason: string, line: int}|null
     */
    private function resolveRemoteFetchForContent(AnalysisObject $ao, string $contentArg, int $fallbackLine): ?array
    {
        $direct = $this->resolveRemoteFetchInExpression($ao, $contentArg, 0);
        if ($direct !== null) {
            return ['reason' => $direct, 'line' => $fallbackLine];
        }

        $assignment = $this->resolveAssignedContentProvenance($ao, $contentArg);
        if ($assignment !== null) {
            $reason = $this->resolveRemoteFetchInExpression($ao, $assignment->expression, 0);
            if ($reason !== null) {
                return ['reason' => $reason, 'line' => $assignment->line];
            }
        }

        return null;
    }

    /**
     * Determine whether $expression itself represents remote-fetched content,
     * either by directly embedding a call that is provably remote, or by
     * following a bare-variable provenance chain (bounded depth) back to one.
     */
    private function resolveRemoteFetchInExpression(AnalysisObject $ao, string $expression, int $depth): ?string
    {
        $expression = trim($expression);
        if ($expression === '' || $depth > self::REMOTE_FETCH_MAX_DEPTH) {
            return null;
        }

        // wp_remote_retrieve_body(wp_remote_get(...)) / wp_remote_retrieve_body(wp_remote_post(...))
        if (preg_match('/\bwp_remote_retrieve_body\s*\(/i', $expression) === 1) {
            $inner = $this->extractDecoderArgument($expression, 'wp_remote_retrieve_body');
            if ($inner !== null) {
                if (preg_match('/\b(wp_remote_get|wp_remote_post)\s*\(/i', $inner) === 1) {
                    return 'wp_remote_retrieve_body() reads the response body of a wp_remote_get()/wp_remote_post() network request';
                }
                if (preg_match('/^\$[a-zA-Z_][\w]*$/', $inner) === 1) {
                    $innerAssignment = $ao->findAssignmentForVariable($inner);
                    if ($innerAssignment !== null) {
                        $names = array_map('strtolower', $innerAssignment->functionNames);
                        if (in_array('wp_remote_get', $names, true) || in_array('wp_remote_post', $names, true)) {
                            return 'wp_remote_retrieve_body() reads the response body of a wp_remote_get()/wp_remote_post() network request';
                        }
                    }
                }
            }
        }

        // Directly embedded file_get_contents()/fopen() with an established remote URL argument.
        foreach (self::POSSIBLY_REMOTE as $func) {
            if (preg_match('/\b' . preg_quote($func, '/') . '\s*\(/i', $expression) === 1) {
                $urlArg = $this->extractDecoderArgument($expression, $func);
                if ($urlArg !== null && $this->argumentLooksLikeRemoteUrl($ao, $urlArg, 0)) {
                    return sprintf('%s() is called with a remote URL argument', $func);
                }
            }
        }

        // Directly embedded curl_exec($ch) with RETURNTRANSFER enabled and a remote curl_init() URL.
        if (preg_match('/\bcurl_exec\s*\(/i', $expression) === 1) {
            $chArg = $this->extractDecoderArgument($expression, 'curl_exec');
            if ($chArg !== null && $this->curlHandleIsRemoteWithReturnTransfer($ao, $chArg)) {
                return 'curl_exec() returns the transferred response body from a curl handle initialised with a remote URL and CURLOPT_RETURNTRANSFER enabled';
            }
        }

        // Bare variable — follow the assignment provenance chain.
        if (preg_match('/^\$[a-zA-Z_][\w]*$/', $expression) === 1) {
            $assignment = $ao->findAssignmentForVariable($expression);
            if ($assignment !== null) {
                return $this->resolveRemoteFetchInExpression($ao, $assignment->expression, $depth + 1);
            }
        }

        return null;
    }

    /**
     * True only when $chVar is a curl handle variable whose own provenance
     * shows it was initialised via curl_init() with a remote URL, AND a
     * curl_setopt($chVar, CURLOPT_RETURNTRANSFER, true) call exists for that
     * same variable. curl_exec() does not return the transferred body unless
     * CURLOPT_RETURNTRANSFER is enabled, so both facts must be established.
     */
    private function curlHandleIsRemoteWithReturnTransfer(AnalysisObject $ao, string $chVar): bool
    {
        $chVar = trim($chVar);
        if (preg_match('/^\$[a-zA-Z_][\w]*$/', $chVar) !== 1) {
            return false;
        }

        $initAssignment = $ao->findAssignmentForVariable($chVar);
        if ($initAssignment === null
            || !in_array('curl_init', array_map('strtolower', $initAssignment->functionNames), true)
        ) {
            return false;
        }

        $urlArg = $this->extractDecoderArgument($initAssignment->expression, 'curl_init');
        if ($urlArg === null || !$this->argumentLooksLikeRemoteUrl($ao, $urlArg, 0)) {
            return false;
        }

        foreach ($ao->functionCalls as $call) {
            if (strtolower($call->name) !== 'curl_setopt' || count($call->args) < 3) {
                continue;
            }
            if (trim($call->args[0]) !== $chVar) {
                continue;
            }
            if (preg_match('/CURLOPT_RETURNTRANSFER/i', $call->args[1]) !== 1) {
                continue;
            }
            $value = strtolower(trim($call->args[2]));
            if ($value === 'true' || $value === '1') {
                return true;
            }
        }

        return false;
    }

    /**
     * Build a finding for suspicious creation of executable PHP payloads.
     * A .php destination alone is not enough; require corroboration that the
     * written content is likely executable payload material rather than normal
     * application output.
     */
    private function buildSuspiciousExecutablePayloadWriteFinding(AnalysisObject $ao, array $writeCalls): ?Finding
    {
        $execWrite = $this->findExecutablePathWrite($writeCalls);
        if ($execWrite === null) {
            return null;
        }

        $dest = trim($execWrite->args[0] ?? '?');
        $contentArg = trim($execWrite->args[1] ?? '');
        $currentFile = (string) ($ao->meta->filePath ?? '');

        $hasExecution = $ao->hasFunctionCall('eval') || $ao->hasFunctionCall('assert');
        $hasDangerousInput = $ao->hasUserInput();
        $hasDynamicDispatch = !empty($ao->features->dynamicDispatchCalls);
        $hasEncodedPayload = !empty($ao->features->encodedBlobs);
        $hasElevatedObfuscation = $ao->features->obfuscationScore >= 0.35;
        $payloadIocs = $this->extractSuspiciousPayloadIocs($ao->iocs, $currentFile);
        $contentAssignment = $this->resolveAssignedContentProvenance($ao, $contentArg);
        $contentLooksExecutable = $this->writeContentLooksExecutablePhp($contentArg, $ao);
        $contentLooksDecodedOrConstructed = $this->writeContentLooksDecodedOrConstructedPayload($contentArg)
            || ($contentAssignment !== null && $this->assignmentLooksDecodedOrConstructed($contentAssignment));
        $contentUsesDangerousInput = $this->writeContentUsesUserInput($contentArg)
            || ($contentAssignment !== null && $contentAssignment->usesUserInput);

        $signals = ['writes to a server-executable path'];
        $evidence = [
            $this->makeEvidence(
                $execWrite->line,
                $this->snippet($ao->rawContent, $execWrite->line),
                'Write to executable path: ' . $execWrite->name . '(' . $dest . ')',
            ),
        ];

        if ($contentLooksExecutable) {
            $signals[] = 'written content looks like executable PHP payload code';
        }
        if ($contentLooksDecodedOrConstructed) {
            $signals[] = 'written content is decoded or dynamically constructed';
        }
        if ($contentUsesDangerousInput) {
            $signals[] = 'written content includes attacker-controlled input';
        }
        if ($hasExecution) {
            $signals[] = 'contains direct code-execution capability';
        }
        if ($hasDynamicDispatch) {
            $signals[] = 'uses dynamic dispatch';
            $dynamic = $ao->features->dynamicDispatchCalls[0];
            [$name, $line] = $this->splitFeatureCallEvidence($dynamic);
            if ($line !== null) {
                $evidence[] = $this->makeEvidence(
                    $line,
                    $this->snippet($ao->rawContent, $line),
                    'Dynamic dispatch: ' . $name . '()',
                );
            }
        }
        if ($hasEncodedPayload) {
            $signals[] = 'contains encoded payload material';
            $evidence[] = $this->makeEvidence(
                $execWrite->line,
                $this->snippet($ao->rawContent, $execWrite->line),
                'Encoded blob evidence: ' . $ao->features->encodedBlobs[0],
            );
        }
        if ($hasElevatedObfuscation) {
            $signals[] = sprintf('has elevated obfuscation score (%.2f)', $ao->features->obfuscationScore);
        }
        if ($hasDangerousInput) {
            $signals[] = 'processes attacker-controlled input';
        }
        if (!empty($payloadIocs)) {
            $signals[] = 'contains payload/network IOCs';
            $firstIoc = $payloadIocs[0];
            $evidence[] = $this->makeEvidence(
                $firstIoc->line,
                $this->snippet($ao->rawContent, $firstIoc->line),
                'Associated IOC: ' . $firstIoc->value,
            );
        }

        $hasStrongPayloadCorroboration = $contentUsesDangerousInput
            || ($contentLooksExecutable && ($hasExecution || $hasEncodedPayload || $hasElevatedObfuscation || $hasDangerousInput || $hasDynamicDispatch || !empty($payloadIocs)))
            || ($contentLooksDecodedOrConstructed && ($hasEncodedPayload || $hasElevatedObfuscation || $hasExecution || $hasDangerousInput))
            || ($contentUsesDangerousInput && ($contentLooksExecutable || $hasExecution || $hasDynamicDispatch))
            || ($hasExecution && ($contentLooksExecutable || $hasEncodedPayload || $hasDangerousInput))
            || (!empty($payloadIocs) && ($contentLooksExecutable || $hasEncodedPayload || $hasExecution));

        if (!$hasStrongPayloadCorroboration) {
            return null;
        }

        $severity = ($hasExecution || $hasElevatedObfuscation || $contentUsesDangerousInput)
            ? Severity::CRITICAL
            : Severity::HIGH;

        return Finding::create([
            'ruleId'      => 'DROP-003',
            'title'       => sprintf('Suspicious executable payload write: %s(%s)', $execWrite->name, $dest),
            'filePath'    => $currentFile,
            'line'        => $execWrite->line,
            'severity'    => $severity,
            'confidence'  => count($signals) >= 3 ? Confidence::HIGH : Confidence::MEDIUM,
            'category'    => DetectionCategory::PERSISTENCE,
            'description' => sprintf(
                'This file writes content to a server-executable path (%s) using %s(), with corroborating signals that the written content is suspicious executable PHP payload material.',
                $dest,
                $execWrite->name,
            ),
            'explanation' => 'Creating a .php-like file is not automatically malicious, but it becomes high risk when the written content also looks executable, decoded, user-controlled, or otherwise correlated with payload-installation behaviour. This pattern is consistent with a script that creates a persistent PHP payload.',
            'remediation' => 'Verify whether this executable file creation is intentional and authorised. If not, inspect the written payload source, remove both the writer and generated payload, and review nearby files for related persistence.',
            'evidence'    => $evidence,
            'iocs'        => $payloadIocs,
            'tags'        => ['dropper', 'php-file-create', 'payload-write', 'persistence'],
        ]);
    }

    private function buildSuspiciousWpConfigModificationFinding(AnalysisObject $ao, array $writeCalls): ?Finding
    {
        $configWrite = $this->findWriteCallByPathSuffix($writeCalls, 'wp-config.php');
        if ($configWrite === null) {
            return null;
        }

        $contentArg = trim($configWrite->args[1] ?? '');
        $currentFile = (string) ($ao->meta->filePath ?? '');
        $hasExecution = $ao->hasFunctionCall('eval') || $ao->hasFunctionCall('assert');
        $hasDangerousInput = $ao->hasUserInput();
        $hasDynamicDispatch = !empty($ao->features->dynamicDispatchCalls);
        $hasEncodedPayload = !empty($ao->features->encodedBlobs);
        $hasElevatedObfuscation = $ao->features->obfuscationScore >= 0.35;
        $payloadIocs = $this->extractSuspiciousPayloadIocs($ao->iocs, $currentFile);
        $contentAssignment = $this->resolveAssignedContentProvenance($ao, $contentArg);
        $contentLooksExecutable = $this->writeContentLooksExecutablePhp($contentArg, $ao);
        $contentLooksDecodedOrConstructed = $this->writeContentLooksDecodedOrConstructedPayload($contentArg)
            || ($contentAssignment !== null && $this->assignmentLooksDecodedOrConstructed($contentAssignment));
        $contentUsesDangerousInput = $this->writeContentUsesUserInput($contentArg)
            || ($contentAssignment !== null && $contentAssignment->usesUserInput);
        $contentTouchesConfigSecrets = preg_match('/DB_(NAME|USER|PASSWORD|HOST)|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|\$table_prefix|define\s*\(/i', $contentArg) === 1;

        $signals = ['writes to wp-config.php'];
        if ($contentLooksExecutable) {
            $signals[] = 'written content looks like executable PHP';
        }
        if ($contentLooksDecodedOrConstructed) {
            $signals[] = 'written content is decoded or dynamically constructed';
        }
        if ($contentUsesDangerousInput || $hasDangerousInput) {
            $signals[] = 'uses attacker-controlled input';
        }
        if ($contentTouchesConfigSecrets) {
            $signals[] = 'modifies WordPress configuration/secrets';
        }
        if ($hasEncodedPayload) {
            $signals[] = 'contains encoded payload material';
        }
        if ($hasElevatedObfuscation) {
            $signals[] = sprintf('has elevated obfuscation score (%.2f)', $ao->features->obfuscationScore);
        }
        if ($hasExecution) {
            $signals[] = 'contains direct code-execution capability';
        }
        if ($hasDynamicDispatch) {
            $signals[] = 'uses dynamic dispatch';
        }

        return Finding::create([
            'ruleId'      => 'DROP-005',
            'title'       => 'Suspicious wp-config.php modification',
            'filePath'    => $currentFile,
            'line'        => $configWrite->line,
            'severity'    => ($hasExecution || $contentUsesDangerousInput || $contentTouchesConfigSecrets) ? Severity::CRITICAL : Severity::HIGH,
            'confidence'  => count($signals) >= 3 ? Confidence::HIGH : Confidence::MEDIUM,
            'category'    => DetectionCategory::PERSISTENCE,
            'description' => 'This file writes or modifies wp-config.php with correlated suspicious content or behavior.',
            'explanation' => 'wp-config.php references alone are common and legitimate, but actual writes to wp-config.php become high risk when correlated with executable PHP content, decoded or obfuscated payload material, attacker-controlled input, secret/config manipulation, or other payload-oriented behavior. Correlated signals: ' . implode('; ', $signals) . '.',
            'remediation' => 'Inspect the wp-config.php write path immediately. Restore wp-config.php from a trusted backup if altered unexpectedly, rotate WordPress salts and database credentials if exposed, and remove the writer if malicious.',
            'evidence'    => [
                $this->makeEvidence(
                    $configWrite->line,
                    $this->snippet($ao->rawContent, $configWrite->line),
                    'Write to wp-config.php: ' . $configWrite->name . '(' . trim($configWrite->args[0] ?? '?') . ')',
                ),
            ],
            'iocs'        => $payloadIocs,
            'tags'        => ['dropper', 'wp-config', 'config-modification', 'persistence'],
        ]);
    }

    private function buildSuspiciousHtaccessModificationFinding(AnalysisObject $ao, array $writeCalls): ?Finding
    {
        $htaccessWrite = $this->findWriteCallByPathComponent($writeCalls, '.htaccess');
        if ($htaccessWrite === null) {
            return null;
        }

        $contentArg = trim($htaccessWrite->args[1] ?? '');
        $currentFile = (string) ($ao->meta->filePath ?? '');
        $hasExecution = $ao->hasFunctionCall('eval') || $ao->hasFunctionCall('assert');
        $hasDangerousInput = $ao->hasUserInput();
        $hasDynamicDispatch = !empty($ao->features->dynamicDispatchCalls);
        $hasEncodedPayload = !empty($ao->features->encodedBlobs);
        $hasElevatedObfuscation = $ao->features->obfuscationScore >= 0.35;
        $payloadIocs = $this->extractSuspiciousPayloadIocs($ao->iocs, $currentFile);
        $contentAssignment = $this->resolveAssignedContentProvenance($ao, $contentArg);
        $rulesAssignments = $this->findAssignmentsForVariable($ao, $contentArg);
        $redirectAssignment = $this->extractFirstAssignedVariableProvenance($ao, $contentAssignment);
        $redirectAssignments = $this->findAssignmentsForVariable($ao, '$redirect');
        $injectsHtaccessRules = preg_match('/RewriteRule|RewriteCond|php_value|php_flag|SetHandler|AddHandler|AddType|auto_(prepend|append)_file|ExecCGI/i', $contentArg) === 1;
        $injectsMaliciousRedirect = preg_match('/https?:\/\/|HTTP_USER_AGENT|bot|spider|crawl|Redirect\s+30[12]/i', $contentArg) === 1;
        $injectsPhpExecutionChange = preg_match('/application\/x-httpd-php|php_flag\s+engine\s+on|SetHandler|AddHandler|AddType|ExecCGI|auto_(prepend|append)_file/i', $contentArg) === 1;
        $contentUsesDangerousInput = $this->writeContentUsesUserInput($contentArg)
            || ($contentAssignment !== null && $contentAssignment->usesUserInput);
        $contentLooksDecodedOrConstructed = $this->writeContentLooksDecodedOrConstructedPayload($contentArg);

        $hasStrongCorroboration = ($injectsHtaccessRules && ($injectsMaliciousRedirect || $injectsPhpExecutionChange || $contentUsesDangerousInput || $hasEncodedPayload || $hasElevatedObfuscation || $hasExecution))
            || ($contentUsesDangerousInput && ($injectsHtaccessRules || $injectsMaliciousRedirect || $injectsPhpExecutionChange))
            || ($contentLooksDecodedOrConstructed && ($injectsHtaccessRules || $injectsMaliciousRedirect || $injectsPhpExecutionChange))
            || (!empty($payloadIocs) && ($injectsMaliciousRedirect || $injectsPhpExecutionChange));

        if (!$hasStrongCorroboration) {
            return null;
        }

        $signals = ['writes to .htaccess'];
        if ($injectsHtaccessRules) {
            $signals[] = 'injects rewrite or server directives';
        }
        if ($injectsMaliciousRedirect) {
            $signals[] = 'contains redirect or cloaking-oriented directives';
        }
        if ($injectsPhpExecutionChange) {
            $signals[] = 'changes PHP execution behavior';
        }
        if ($contentUsesDangerousInput || $hasDangerousInput) {
            $signals[] = 'uses attacker-controlled input';
        }
        if ($contentLooksDecodedOrConstructed) {
            $signals[] = 'written content is decoded or dynamically constructed';
        }
        if ($hasEncodedPayload) {
            $signals[] = 'contains encoded payload material';
        }
        if ($hasElevatedObfuscation) {
            $signals[] = sprintf('has elevated obfuscation score (%.2f)', $ao->features->obfuscationScore);
        }

        return Finding::create([
            'ruleId'      => 'DROP-006',
            'title'       => 'Suspicious .htaccess modification',
            'filePath'    => $currentFile,
            'line'        => $htaccessWrite->line,
            'severity'    => ($injectsPhpExecutionChange || $contentUsesDangerousInput || $hasExecution) ? Severity::CRITICAL : Severity::HIGH,
            'confidence'  => count($signals) >= 3 ? Confidence::HIGH : Confidence::MEDIUM,
            'category'    => DetectionCategory::PERSISTENCE,
            'description' => 'This file writes or modifies .htaccess with correlated suspicious redirect, execution, or injected-rule behavior.',
            'explanation' => 'Normal .htaccess references are not enough to flag, but actual writes become suspicious when the injected content enables malicious redirects, PHP execution changes, stealth persistence directives, or user-controlled/obfuscated rule injection. Correlated signals: ' . implode('; ', $signals) . '.',
            'remediation' => 'Inspect the .htaccess write path and review the generated directives. Remove unexpected redirect or PHP-execution changes, restore the original .htaccess if needed, and remove the modifying script if malicious.',
            'evidence'    => [
                $this->makeEvidence(
                    $htaccessWrite->line,
                    $this->snippet($ao->rawContent, $htaccessWrite->line),
                    'Write to .htaccess: ' . $htaccessWrite->name . '(' . trim($htaccessWrite->args[0] ?? '?') . ')',
                ),
            ],
            'iocs'        => $payloadIocs,
            'tags'        => ['dropper', 'htaccess', 'directive-injection', 'persistence'],
        ]);
    }

    /** Returns the first write call with a statically evident executable destination path, or null. */
    private function findExecutablePathWrite(array $writeCalls): ?FunctionCall
    {
        foreach ($writeCalls as $call) {
            if ($this->isStaticallyExecutablePath($call->args[0] ?? '')) {
                return $call;
            }
        }
        return null;
    }

    private function findWriteCallByLiteralSuffix(array $writeCalls, string $suffix): ?FunctionCall
    {
        $suffix = strtolower($suffix);

        foreach ($writeCalls as $call) {
            $arg = trim($call->args[0] ?? '');
            if (!preg_match('/^[\'"](.+)[\'"]$/', $arg, $m)) {
                continue;
            }

            if (str_ends_with(strtolower($m[1]), $suffix)) {
                return $call;
            }
        }

        return null;
    }

    private function findWriteCallByPathComponent(array $writeCalls, string $pathComponent): ?FunctionCall
    {
        $pattern = "~(?:^|[\\/'\".\\s])" . preg_quote(strtolower($pathComponent), '~') . "(?:$|[\\/'\"\\s\\]\\)])~";

        foreach ($writeCalls as $call) {
            $arg = strtolower(trim($call->args[0] ?? ''));
            if ($arg === '') {
                continue;
            }

            if (preg_match($pattern, $arg) === 1) {
                return $call;
            }
        }

        return null;
    }

    private function findWriteCallByPathSuffix(array $writeCalls, string $suffix): ?FunctionCall
    {
        $suffix = strtolower($suffix);

        foreach ($writeCalls as $call) {
            $arg = strtolower(trim($call->args[0] ?? ''));
            if ($arg === '') {
                continue;
            }

            if (str_contains($arg, $suffix)) {
                return $call;
            }
        }

        return null;
    }

    /**
     * @param IOC[] $iocs
     * @return IOC[]
     */
    private function extractSuspiciousPayloadIocs(array $iocs, string $currentFile): array
    {
        $matches = [];

        foreach ($iocs as $ioc) {
            if ($ioc->filePath !== $currentFile) {
                continue;
            }

            if ($ioc->type === IOCType::URL || $ioc->type === IOCType::DOMAIN || $ioc->isConfirmedMalicious) {
                $matches[] = $ioc;
            }
        }

        return $matches;
    }

    /** @return array{0: string, 1: ?int} */
    private function splitFeatureCallEvidence(string $evidence): array
    {
        $parts = explode(':', $evidence);
        if (count($parts) < 2) {
            return [$evidence, null];
        }

        $line = ctype_digit($parts[count($parts) - 1]) ? (int) $parts[count($parts) - 1] : null;
        array_pop($parts);

        return [implode(':', $parts), $line];
    }

    private function describeWriteDestination(FunctionCall $call): string
    {
        return trim($call->args[0] ?? '?');
    }

    private function writeContentLooksExecutablePhp(string $contentArg, AnalysisObject $ao): bool
    {
        $contentArg = strtolower($contentArg);
        if ($contentArg === '') {
            return false;
        }

        if (str_contains($contentArg, '<?php') || str_contains($contentArg, '<?=') || str_contains($contentArg, '<?=')) {
            return true;
        }

        foreach ($ao->strings as $string) {
            $value = strtolower($string->value);
            if ((str_contains($value, '<?php') || str_contains($value, '<?=') || str_contains($value, '<?='))
                && str_contains($contentArg, strtolower($string->value))
            ) {
                return true;
            }
        }

        return false;
    }

    private function writeContentLooksDecodedOrConstructedPayload(string $contentArg): bool
    {
        $lower = strtolower($contentArg);

        foreach (self::DECODE_FUNCS as $func) {
            if (str_contains($lower, $func . '(')) {
                return true;
            }
        }

        if (str_contains($contentArg, '.')) {
            return true;
        }

        return preg_match('/\$[a-zA-Z_][\w]*\s*\./', $contentArg) === 1
            || preg_match('/\.\s*\$[a-zA-Z_][\w]*/', $contentArg) === 1;
    }

    private function writeContentUsesUserInput(string $contentArg): bool
    {
        return preg_match('/\$_(POST|GET|REQUEST|COOKIE|SERVER|FILES)\b/', $contentArg) === 1;
    }

    /** True when $arg's final effective static path suffix is provably server-executable. */
    private function isStaticallyExecutablePath(string $arg): bool
    {
        $suffix = $this->extractStaticPathSuffix($arg);
        if ($suffix === null) {
            return false;
        }

        $path = strtolower($suffix);
        foreach (self::EXECUTABLE_EXTS as $ext) {
            if (str_ends_with($path, '.' . $ext)) {
                return true;
            }
        }
        return false;
    }

    private function extractStaticPathSuffix(string $expression): ?string
    {
        $segments = $this->decomposePathExpressionIntoSegments($expression);
        if ($segments === null || $segments === []) {
            return null;
        }

        $suffix = '';
        for ($i = count($segments) - 1; $i >= 0; $i--) {
            if ($segments[$i]['type'] !== 'static') {
                return $suffix !== '' ? $suffix : null;
            }

            $suffix = $segments[$i]['value'] . $suffix;
        }

        return $suffix !== '' ? $suffix : null;
    }

    /**
     * @return list<array{type: 'static'|'dynamic', value: string}>
     */
    private function decomposePathExpressionIntoSegments(string $expression): ?array
    {
        $trimmed = trim($expression);
        if ($trimmed === '') {
            return null;
        }

        $literal = $this->extractStringLiteralValue($trimmed);
        if ($literal !== null) {
            return [['type' => 'static', 'value' => $literal]];
        }

        $unwrapped = $this->unwrapBalancedParenthesizedExpression($trimmed);
        if ($unwrapped !== $trimmed) {
            return $this->decomposePathExpressionIntoSegments($unwrapped);
        }

        $parts = $this->splitTopLevelConcatenationParts($trimmed);
        if ($parts === null) {
            return [['type' => 'dynamic', 'value' => '']];
        }

        $segments = [];
        foreach ($parts as $part) {
            $subSegments = $this->decomposePathExpressionIntoSegments($part);
            if ($subSegments === null || $subSegments === []) {
                $segments[] = ['type' => 'dynamic', 'value' => ''];
                continue;
            }

            foreach ($subSegments as $segment) {
                $segments[] = $segment;
            }
        }

        return $segments;
    }

    private function extractStringLiteralValue(string $expression): ?string
    {
        $trimmed = trim($expression);
        if ($trimmed === '') {
            return null;
        }

        $first = $trimmed[0];
        if (($first !== "'" && $first !== '"') || substr($trimmed, -1) !== $first) {
            return null;
        }

        $body = substr($trimmed, 1, -1);
        if ($body === false) {
            return null;
        }

        return stripcslashes($body);
    }

    private function unwrapBalancedParenthesizedExpression(string $expression): string
    {
        $trimmed = trim($expression);
        while ($this->isWrappedInBalancedParentheses($trimmed)) {
            $trimmed = trim(substr($trimmed, 1, -1));
        }

        return $trimmed;
    }

    private function isWrappedInBalancedParentheses(string $expression): bool
    {
        $length = strlen($expression);
        if ($length < 2 || $expression[0] !== '(' || $expression[$length - 1] !== ')') {
            return false;
        }

        $depthParen = 0;
        $depthBracket = 0;
        $depthBrace = 0;
        $inSingle = false;
        $inDouble = false;
        $escaped = false;

        for ($i = 0; $i < $length; $i++) {
            $char = $expression[$i];

            if ($inSingle) {
                if ($escaped) {
                    $escaped = false;
                    continue;
                }
                if ($char === '\\') {
                    $escaped = true;
                    continue;
                }
                if ($char === "'") {
                    $inSingle = false;
                }
                continue;
            }

            if ($inDouble) {
                if ($escaped) {
                    $escaped = false;
                    continue;
                }
                if ($char === '\\') {
                    $escaped = true;
                    continue;
                }
                if ($char === '"') {
                    $inDouble = false;
                }
                continue;
            }

            if ($char === "'") {
                $inSingle = true;
                continue;
            }
            if ($char === '"') {
                $inDouble = true;
                continue;
            }

            if ($char === '(') {
                $depthParen++;
                continue;
            }
            if ($char === ')') {
                $depthParen--;
                if ($depthParen === 0 && $i !== $length - 1) {
                    return false;
                }
                if ($depthParen < 0) {
                    return false;
                }
                continue;
            }
            if ($char === '[') {
                $depthBracket++;
                continue;
            }
            if ($char === ']') {
                $depthBracket--;
                if ($depthBracket < 0) {
                    return false;
                }
                continue;
            }
            if ($char === '{') {
                $depthBrace++;
                continue;
            }
            if ($char === '}') {
                $depthBrace--;
                if ($depthBrace < 0) {
                    return false;
                }
                continue;
            }
        }

        return $depthParen === 0 && $depthBracket === 0 && $depthBrace === 0 && !$inSingle && !$inDouble;
    }

    /** @return list<string>|null */
    private function splitTopLevelConcatenationParts(string $expression): ?array
    {
        $tokenizer = new PhpTokenizer();
        $result = $tokenizer->tokenize("<?php " . $expression . ';', 'dropper-path-expression');
        if (!empty($result->parseErrors)) {
            return null;
        }

        $tokens = $result->tokens;
        $parts = [];
        $current = '';
        $depthParen = 0;
        $depthBracket = 0;
        $depthBrace = 0;
        $sawConcat = false;
        $started = false;

        foreach ($tokens as $token) {
            if ($token->id === T_OPEN_TAG) {
                continue;
            }

            if (!$started && $this->isIgnorableExpressionToken($token)) {
                continue;
            }
            $started = true;

            if ($token->text === ';' && $depthParen === 0 && $depthBracket === 0 && $depthBrace === 0) {
                break;
            }

            if ($this->isIgnorableExpressionToken($token)) {
                $current .= $token->text;
                continue;
            }

            if ($token->text === '(') {
                $depthParen++;
                $current .= $token->text;
                continue;
            }
            if ($token->text === ')') {
                $depthParen--;
                $current .= $token->text;
                continue;
            }
            if ($token->text === '[') {
                $depthBracket++;
                $current .= $token->text;
                continue;
            }
            if ($token->text === ']') {
                $depthBracket--;
                $current .= $token->text;
                continue;
            }
            if ($token->text === '{') {
                $depthBrace++;
                $current .= $token->text;
                continue;
            }
            if ($token->text === '}') {
                $depthBrace--;
                $current .= $token->text;
                continue;
            }

            if ($token->text === '.' && $depthParen === 0 && $depthBracket === 0 && $depthBrace === 0) {
                $parts[] = trim($current);
                $current = '';
                $sawConcat = true;
                continue;
            }

            $current .= $token->text;
        }

        if (!$sawConcat) {
            return null;
        }

        $parts[] = trim($current);
        return $parts;
    }

    private function isIgnorableExpressionToken(Token $token): bool
    {
        return in_array($token->id, [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true);
    }



    private function resolveAssignedContentProvenance(AnalysisObject $ao, string $contentArg): ?\Wpma\Models\VariableAssignment
    {
        if (preg_match('/^\$[a-zA-Z_][\w]*$/', trim($contentArg)) !== 1) {
            return null;
        }

        return $ao->findAssignmentForVariable(trim($contentArg));
    }

    /**
     * Build a DROP-002 finding only when BOTH of the following are established
     * for the SAME operation:
     *
     *   1. A specific write call's OWN content argument actually derives from
     *      a decode operation (directly embedded, or via the existing
     *      variable-assignment provenance chain).
     *   2. That SAME decode call's OWN input argument has suspicious
     *      provenance (request/superglobal data, a remote fetch, another
     *      decoded/constructed payload, or a substantial embedded encoded
     *      blob) — not merely a local read (e.g. archive/stream decompression).
     *
     * Decode and write functions merely coexisting in the file, or a
     * decoder whose own input cannot be shown to be suspicious, is NOT
     * sufficient to emit this finding.
     */
    private function buildDecoderWriterFinding(AnalysisObject $ao, array $writeCalls): ?Finding
    {
        $currentFile = (string) ($ao->meta->filePath ?? '');

        foreach ($writeCalls as $writeCall) {
            $contentArg = trim($writeCall->args[1] ?? '');
            if ($contentArg === '') {
                continue;
            }

            $decodeLine        = $writeCall->line;
            $viaProvenance     = false;
            $decoderSourceExpr = $contentArg;
            $decodeFunction    = $this->findDirectDecodeFunctionInExpression($contentArg);

            if ($decodeFunction === null) {
                $contentAssignment = $this->resolveAssignedContentProvenance($ao, $contentArg);
                if ($contentAssignment !== null) {
                    $decodeFunction = $this->findDecodeFunctionInAssignment($contentAssignment);
                    if ($decodeFunction !== null) {
                        $decodeLine        = $contentAssignment->line;
                        $viaProvenance     = true;
                        $decoderSourceExpr = $contentAssignment->expression;
                    }
                }
            }

            if ($decodeFunction === null) {
                continue;
            }

            // Data flow to the write is established. Now require the decoder's
            // OWN input to be independently suspicious before treating this as
            // a payload dropper rather than ordinary decompression/decoding.
            $decoderInputArg = $this->extractDecoderArgument($decoderSourceExpr, $decodeFunction);
            if ($decoderInputArg === null || $decoderInputArg === '') {
                continue; // cannot establish decoder input — do not guess
            }

            $suspiciousReason = $this->classifySuspiciousDecoderInput($ao, $decoderInputArg);
            if ($suspiciousReason === null) {
                continue; // decoder input provenance is not suspicious — do not emit
            }

            $writesExe = $this->isStaticallyExecutablePath($writeCall->args[0] ?? '');
            $severity  = $writesExe ? Severity::CRITICAL : Severity::HIGH;

            $decodeEvidenceLabel = $viaProvenance
                ? sprintf('Decode via assignment: %s()', $decodeFunction)
                : sprintf('Decode: %s()', $decodeFunction);

            return Finding::create([
                'ruleId'      => 'DROP-002',
                'title'       => sprintf('Decoder-writer: %s() result written to file', $decodeFunction),
                'filePath'    => $currentFile,
                'line'        => $decodeLine,
                'severity'    => $severity,
                'confidence'  => Confidence::HIGH,
                'category'    => DetectionCategory::PERSISTENCE,
                'description' => sprintf(
                    'This file decodes content (%s()) and writes it to the filesystem (%s()) '
                    . '— the write content directly derives from the decoded value, and %s.',
                    $decodeFunction,
                    $writeCall->name,
                    $suspiciousReason,
                ),
                'explanation' => 'Decoding followed by a file write is used to install obfuscated '
                    . 'payloads without making an outbound network connection. The payload is embedded '
                    . 'in the dropper itself (base64, gzip, rot13, etc.), decoded at runtime, and '
                    . 'written to a new file — typically a PHP backdoor that persists after the '
                    . 'original dropper is removed. This finding requires BOTH that the write content '
                    . 'derives from the decode operation AND that the decoder\'s own input is itself '
                    . 'suspicious (request data, a remote fetch, another decoded payload, or a substantial '
                    . 'embedded encoded blob) — ordinary local decompression/extraction (e.g. reading '
                    . 'compressed bytes from a local file/stream and inflating them) does not qualify.',
                'remediation' => 'Decode the payload manually to inspect its content. '
                    . 'Delete both this dropper file and any generated payload files.',
                'evidence'    => [
                    $this->makeEvidence(
                        $decodeLine,
                        $this->snippet($ao->rawContent, $decodeLine),
                        $decodeEvidenceLabel,
                    ),
                    $this->makeEvidence(
                        $writeCall->line,
                        $this->snippet($ao->rawContent, $writeCall->line),
                        'Write: ' . $writeCall->name . '()',
                    ),
                ],
                'tags' => ['dropper', 'decode-write', 'obfuscation', 'persistence'],
            ]);
        }

        return null;
    }

    /**
     * Extract the decode function's own first argument expression from
     * $expression (which is either the write call's own content-argument
     * text, or a resolved VariableAssignment's expression text). Operates
     * purely on the already-extracted expression string — no rereading or
     * retokenizing of the file.
     */
    private function extractDecoderArgument(string $expression, string $decodeFunction): ?string
    {
        if (preg_match('/\b' . preg_quote($decodeFunction, '/') . '\s*\(/i', $expression, $m, PREG_OFFSET_CAPTURE) !== 1) {
            return null;
        }

        $start = $m[0][1] + strlen($m[0][0]);
        $len   = strlen($expression);
        $depth = 1;
        $buf   = '';

        for ($i = $start; $i < $len; $i++) {
            $ch = $expression[$i];

            if ($ch === '(') {
                $depth++;
            } elseif ($ch === ')') {
                $depth--;
                if ($depth === 0) {
                    break;
                }
            } elseif ($ch === ',' && $depth === 1) {
                break; // stop at the first top-level argument separator
            }

            $buf .= $ch;
        }

        $buf = trim($buf);
        return $buf === '' ? null : $buf;
    }

    /**
     * Determine whether a decoder's OWN input argument has suspicious
     * provenance. Returns a short reason string when suspicious, or null
     * when no suspicious origin can be established from existing data —
     * in which case DROP-002 must not fire for this decode/write pairing.
     */
    private function classifySuspiciousDecoderInput(AnalysisObject $ao, string $decoderInputArg): ?string
    {
        $arg = trim($decoderInputArg);
        if ($arg === '') {
            return null;
        }

        if ($this->writeContentUsesUserInput($arg)) {
            return 'the decoder input is directly derived from request/superglobal data';
        }

        if (preg_match('/https?:\/\/|\b(wp_remote_get|wp_remote_post|curl_exec|fsockopen|stream_socket_client)\s*\(/i', $arg) === 1) {
            return 'the decoder input is directly derived from a remote/network fetch';
        }

        if (preg_match('/^\$[a-zA-Z_][\w]*$/', $arg) === 1) {
            $inputAssignment = $ao->findAssignmentForVariable($arg);
            if ($inputAssignment === null) {
                return null; // no provenance available for the decoder's own input — do not guess
            }

            if ($inputAssignment->usesUserInput) {
                return 'the decoder input traces to request/superglobal data';
            }

            if ($this->decoderInputAssignmentIsRemote($inputAssignment)) {
                return 'the decoder input traces to a remote/network fetch';
            }

            if ($this->findDecodeFunctionInAssignment($inputAssignment) !== null) {
                return 'the decoder input traces to another decoded/constructed payload source';
            }

            if ($this->decoderArgumentLooksLikeEncodedBlob($inputAssignment->expression)) {
                return 'the decoder input traces to a substantial embedded encoded blob';
            }

            return null;
        }

        if ($this->decoderArgumentLooksLikeEncodedBlob($arg)) {
            return 'the decoder input is a substantial embedded encoded blob';
        }

        return null;
    }

    /** True when the resolved assignment's own provenance indicates a remote/network fetch. */
    private function decoderInputAssignmentIsRemote(\Wpma\Models\VariableAssignment $assignment): bool
    {
        if (preg_match('/https?:\/\//i', $assignment->expression) === 1) {
            return true;
        }

        foreach ($assignment->functionNames as $functionName) {
            if (in_array(strtolower($functionName), ['wp_remote_get', 'wp_remote_post', 'curl_exec', 'fsockopen', 'stream_socket_client'], true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * True when $expression is itself a quoted string literal that looks like a
     * substantial encoded blob (large base64 or hex payload). Applied only to
     * the specific decoder-argument expression under evaluation — not file-wide.
     */
    private function decoderArgumentLooksLikeEncodedBlob(string $expression): bool
    {
        $expression = trim($expression);
        if (preg_match('/^[\'"](.+)[\'"]$/s', $expression, $m) !== 1) {
            return false;
        }

        $value = $m[1];
        $len   = strlen($value);

        if ($len > 50
            && preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $value) === 1
            && (str_contains($value, '+') || str_contains($value, '/') || str_ends_with($value, '='))
        ) {
            return true;
        }

        if ($len > 100 && preg_match('/^[0-9a-fA-F]+$/', $value) === 1) {
            return true;
        }

        return false;
    }

    /** Returns the decode function name if it is directly called within $expression, or null. */
    private function findDirectDecodeFunctionInExpression(string $expression): ?string
    {
        foreach (self::DECODE_FUNCS as $func) {
            if (preg_match('/\b' . preg_quote($func, '/') . '\s*\(/i', $expression) === 1) {
                return $func;
            }
        }

        return null;
    }

    /** Returns the decode function name found in the assignment's provenance (including propagated chains), or null. */
    private function findDecodeFunctionInAssignment(\Wpma\Models\VariableAssignment $assignment): ?string
    {
        foreach ($assignment->functionNames as $functionName) {
            $lower = strtolower($functionName);
            if (in_array($lower, self::DECODE_FUNCS, true)) {
                return $lower;
            }
        }

        return null;
    }

    private function assignmentLooksDecodedOrConstructed(\Wpma\Models\VariableAssignment $assignment): bool
    {
        foreach ($assignment->functionNames as $functionName) {
            if (in_array(strtolower($functionName), self::DECODE_FUNCS, true)) {
                return true;
            }
        }

        if (str_contains($assignment->expression, '.')) {
            return true;
        }

        return preg_match('/\$[a-zA-Z_][\w]*\s*\./', $assignment->expression) === 1
            || preg_match('/\.\s*\$[a-zA-Z_][\w]*/', $assignment->expression) === 1;
    }

    private function extractFirstAssignedVariableProvenance(AnalysisObject $ao, ?\Wpma\Models\VariableAssignment $assignment): ?\Wpma\Models\VariableAssignment
    {
        if ($assignment === null) {
            return null;
        }

        if (preg_match('/\$[a-zA-Z_][\w]*/', $assignment->expression, $m) !== 1) {
            return null;
        }

        return $ao->findAssignmentForVariable($m[0]);
    }

    private function findAssignmentsForVariable(AnalysisObject $ao, string $variableName): array
    {
        $normalized = trim($variableName);
        if ($normalized === '') {
            return [];
        }

        return array_values(array_filter(
            $ao->assignments,
            static fn($assignment) => $assignment->variableName === $normalized
        ));
    }
}
