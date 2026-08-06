<?php

declare(strict_types=1);

namespace Wpma\Detectors;

use Wpma\Models\AnalysisObject;
use Wpma\Models\Confidence;
use Wpma\Models\DetectionCategory;
use Wpma\Models\Finding;
use Wpma\Models\FunctionCall;
use Wpma\Models\Severity;
use Wpma\Pipeline\CodeContext;

/**
 * BackdoorDetector — detects dangerous function calls, user-input execution,
 * and dynamic dispatch patterns indicative of PHP backdoors.
 *
 * False-positive prevention principles:
 * - Regex-based patterns run ONLY on executable PHP code (comments/strings stripped)
 * - Function calls from the token stream are inspected for argument context
 * - Dangerous functions with static safe arguments produce LOW confidence only
 * - Confidence escalates when multiple risk indicators combine
 * - WP-standard hook functions (call_user_func*) require additional context to flag
 */
class BackdoorDetector extends AbstractDetector
{
    public function getName(): string    { return 'BackdoorDetector'; }
    public function getVersion(): string { return '1.1.0'; }
    public function getRuleId(): string  { return 'BACK'; }

    public function getSupportedExtensions(): array
    {
        return ['.php', '.phtml', '.php5', '.php7', '.phar'];
    }

    // Dangerous functions that warrant inspection
    private const DANGEROUS_FUNCS = [
        'eval', 'assert', 'system', 'exec', 'shell_exec', 'passthru',
        'proc_open', 'popen', 'pcntl_exec', 'create_function',
        'call_user_func', 'call_user_func_array',
    ];

    private const EXECUTION_FUNCS = [
        'system', 'exec', 'shell_exec', 'passthru', 'proc_open', 'popen', 'pcntl_exec',
    ];

    private const CALLBACK_FUNCS = [
        'call_user_func', 'call_user_func_array',
    ];

    private const DYNAMIC_PHP_EXECUTION_FUNCS = [
        'eval', 'assert',
    ];

    // Arguments that indicate a safe static call (exec/system with known paths)
    private const SAFE_ARG_PATTERNS = [
        // Known safe shell commands: image tools, git, etc.
        '#^[\'"](/usr/bin/|/bin/|/usr/local/bin/)\w#',
        // WordPress internal function names passed as string callbacks
        '#^[\'"]wp_#',
        '#^[\'"]sanitize_#',
        '#^[\'"]esc_#',
        // Simple string with no variables and no suspicious content
        '#^\'[a-zA-Z0-9_\-\s/:.]{1,60}\'$#',
        '#^"[a-zA-Z0-9_\-\s/:.]{1,60}"$#',
    ];

    // Arguments that indicate high-risk user-controlled input
    private const DANGEROUS_ARG_PATTERNS = [
        '/\$_(POST|GET|REQUEST|COOKIE|SERVER|FILES)/',
        '/file_get_contents\s*\(\s*[\'"]https?:/',
        '/base64_decode/',
        '/gzinflate/',
        '/gzdecode/',
        '/str_rot13/',
        '/hex2bin/',
        '/php:\/\/input/',
    ];

    // Paths that indicate vendor/library context — lower confidence
    private const VENDOR_PATH_PATTERNS = [
        '/\/vendor\//',
        '/\/phpseclib\//',
        '/\/symfony\//',
        '/\/monolog\//',
        '/\/pear\//',
        '/\/composer\//',
        '/phpseclib/',
    ];

    public function detect(AnalysisObject $ao): array
    {
        $findings = [];
        $content  = $ao->rawContent;
        $file     = $ao->meta->filePath;

        // Global file-level context flags
        $hasUserInput   = $ao->hasUserInput();
        $hasObfuscation = $ao->features->obfuscationScore > 0.35; // Raised from 0.2 to reduce false positives from hash-heavy files

        // If file is in a verified plugin, require stronger obfuscation evidence
        // (security plugins legitimately use base64_decode for checksums)
        if ($hasObfuscation && $this->isVendorPath($file)) {
            $hasObfuscation = $ao->features->obfuscationScore > 0.6;
        }

        // ── 1. Function call detection (from token stream — already PHP-only) ───
        foreach ($ao->functionCalls as $call) {
            $lower = strtolower($call->name);

            if (!\in_array($lower, self::DANGEROUS_FUNCS, true)) {
                continue;
            }

            $finding = null;
            if (\in_array($lower, self::EXECUTION_FUNCS, true)) {
                $finding = $this->detectBack001ExecutionSink($ao, $call, $file, $content);
            } elseif (\in_array($lower, self::CALLBACK_FUNCS, true)) {
                $finding = $this->detectBack001CallbackInvocation($ao, $call, $file, $content);
            } elseif (\in_array($lower, self::DYNAMIC_PHP_EXECUTION_FUNCS, true)) {
                $finding = $this->detectBack001DynamicPhpExecutionSink($ao, $call, $file, $content);
            }

            if ($finding !== null) {
                $findings[] = $finding;
            }
        }

        // ── 1b. Suspicious WordPress administrator creation/promotion ─────────
        $adminCreationFinding = $this->detectSuspiciousWpAdministratorCreation($ao);
        if ($adminCreationFinding !== null) {
            $findings[] = $adminCreationFinding;
        }

        // ── 1c. Suspicious wp_head/wp_footer injection ────────────────────────
        $wpHookInjectionFinding = $this->detectSuspiciousWpHeadFooterInjection($ao);
        if ($wpHookInjectionFinding !== null) {
            $findings[] = $wpHookInjectionFinding;
        }

        // ── 1d. Malicious redirect / credential-theft behaviour ───────────────
        $redirectOrCredentialFinding = $this->detectMaliciousRedirectOrCredentialTheft($ao);
        if ($redirectOrCredentialFinding !== null) {
            $findings[] = $redirectOrCredentialFinding;
        }

        // ── 2. Regex-based patterns — run on executable PHP only ──────────────
        // CodeContext::stripNonExecutable() removes comments, PHPDoc, string literals,
        // and HTML so these patterns NEVER match documentation or SQL backticks.
        $execOnly = CodeContext::stripNonExecutable($content);

        // 2a. Backtick shell execution — ONLY in executable context
        $this->detectBacktick($execOnly, $file, $hasUserInput, $findings);

        // 2b. preg_replace with /e modifier
        $this->detectPregReplaceE($execOnly, $file, $findings);

        // 2c. Variable-variable dispatch ($$var())
        $this->detectVariableVariable($execOnly, $file, $hasObfuscation, $findings);

        return $findings;
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /**
     * Assess whether the function arguments look safe, dangerous, or unknown.
     * Returns: 'safe' | 'dangerous' | 'unknown'
     */
    private function assessArgSafety(array $args): string
    {
        if (empty($args)) {
            return 'unknown';
        }

        $first = trim($args[0]);

        // Check for known safe patterns
        foreach (self::SAFE_ARG_PATTERNS as $pattern) {
            if (preg_match($pattern, $first)) {
                return 'safe';
            }
        }

        // Check for dangerous patterns
        foreach (self::DANGEROUS_ARG_PATTERNS as $pattern) {
            if (preg_match($pattern, $first)) {
                return 'dangerous';
            }
        }

        return 'unknown';
    }

    private function argHasDangerousPattern(array $args): bool
    {
        $combined = implode(' ', $args);
        foreach (self::DANGEROUS_ARG_PATTERNS as $pattern) {
            if (preg_match($pattern, $combined)) {
                return true;
            }
        }
        return false;
    }

    private function isVendorPath(string $filePath): bool
    {
        foreach (self::VENDOR_PATH_PATTERNS as $pattern) {
            if (preg_match($pattern, $filePath)) {
                return true;
            }
        }
        return false;
    }

    private function detectBack001ExecutionSink(AnalysisObject $ao, FunctionCall $call, string $file, string $content): ?Finding
    {
        $commandArg = $this->getExecutionControllingArgument($call);
        if ($commandArg === null) {
            return null;
        }

        $argSafety = $this->assessArgSafety([$commandArg]);
        $hasDangerousPattern = $this->expressionHasDangerousPattern($commandArg);
        $assignment = $this->resolveRelevantAssignmentFromArgsBeforeLine($ao, [$commandArg], $call->line);
        $hasDangerousAssignment = $assignment !== null && (
            $assignment->usesUserInput
            || $this->assignmentContainsDangerousPattern($assignment)
        );

        if ($argSafety === 'safe' && !$hasDangerousPattern && !$hasDangerousAssignment) {
            return null;
        }

        if (!$hasDangerousPattern && !$hasDangerousAssignment) {
            return null;
        }

        $reason = $hasDangerousPattern
            ? "'{$call->name}' called with dangerous command argument"
            : "'{$call->name}' command argument derives from dangerous provenance";
        $severity = ($hasDangerousPattern && $hasDangerousAssignment) ? Severity::CRITICAL : Severity::HIGH;
        $confidence = ($hasDangerousPattern && $hasDangerousAssignment) ? Confidence::HIGH : Confidence::MEDIUM;

        return $this->makeBack001Finding($call, $file, $content, $reason, $severity, $confidence);
    }

    private function detectBack001CallbackInvocation(AnalysisObject $ao, FunctionCall $call, string $file, string $content): ?Finding
    {
        $callbackTarget = trim($call->args[0] ?? '');
        if ($callbackTarget === '') {
            return null;
        }

        $isStaticCallback = $this->isStaticCallbackTarget($callbackTarget);
        if ($isStaticCallback) {
            return null;
        }

        $hasDangerousPattern = $this->expressionHasDangerousPattern($callbackTarget);
        $assignment = $this->resolveSafeCallbackAssignmentBeforeLine($ao, $callbackTarget, $call->line);
        $hasDangerousAssignment = $assignment !== null && (
            $assignment->usesUserInput
            || $this->assignmentContainsDangerousPattern($assignment)
        );

        if (!$hasDangerousPattern && !$hasDangerousAssignment) {
            return null;
        }

        $reason = $hasDangerousPattern
            ? "'{$call->name}' called with attacker-controlled callback target"
            : "'{$call->name}' callback target derives from dangerous provenance";
        $severity = ($hasDangerousPattern && $hasDangerousAssignment) ? Severity::CRITICAL : Severity::HIGH;
        $confidence = ($hasDangerousPattern && $hasDangerousAssignment) ? Confidence::HIGH : Confidence::MEDIUM;

        return $this->makeBack001Finding($call, $file, $content, $reason, $severity, $confidence);
    }

    private function detectBack001DynamicPhpExecutionSink(AnalysisObject $ao, FunctionCall $call, string $file, string $content): ?Finding
    {
        $codeArg = isset($call->args[0]) ? trim($call->args[0]) : '';
        if ($codeArg === '') {
            return null;
        }

        $hasDangerousPattern = $this->expressionHasDangerousPattern($codeArg);
        $assignment = $this->resolveRelevantAssignmentFromArgsBeforeLine($ao, [$codeArg], $call->line);
        $hasDangerousAssignment = $assignment !== null && (
            $assignment->usesUserInput
            || $this->assignmentContainsDangerousPattern($assignment)
        );

        if (!$hasDangerousPattern && !$hasDangerousAssignment) {
            return null;
        }

        $reason = $hasDangerousPattern
            ? "'{$call->name}' called with dangerous executable PHP input"
            : "'{$call->name}' executable PHP input derives from dangerous provenance";
        $severity = ($hasDangerousPattern && $hasDangerousAssignment) ? Severity::CRITICAL : Severity::HIGH;
        $confidence = ($hasDangerousPattern && $hasDangerousAssignment) ? Confidence::HIGH : Confidence::MEDIUM;

        return $this->makeBack001Finding($call, $file, $content, $reason, $severity, $confidence);
    }

    private function makeBack001Finding(FunctionCall $call, string $file, string $content, string $reason, Severity $severity, Confidence $confidence): Finding
    {
        $argDisplay = !empty($call->args) ? implode(', ', array_slice($call->args, 0, 2)) : '...';

        return Finding::create([
            'ruleId'      => 'BACK-001',
            'title'       => "Dangerous Function: {$call->name}({$argDisplay})",
            'filePath'    => $file,
            'line'        => $call->line,
            'severity'    => $severity,
            'confidence'  => $confidence,
            'category'    => DetectionCategory::BACKDOOR,
            'description' => $reason,
            'explanation' => $this->buildExplanation(strtolower($call->name), $reason, $call->args),
            'remediation' => $this->buildRemediation(strtolower($call->name), $severity),
            'evidence'    => [$this->makeEvidence($call->line, $this->snippet($content, $call->line), $reason)],
            'tags'        => ['backdoor', 'code-execution'],
        ]);
    }

    private function getExecutionControllingArgument(FunctionCall $call): ?string
    {
        $name = strtolower($call->name);

        return match ($name) {
            'system', 'exec', 'shell_exec', 'passthru', 'popen', 'pcntl_exec' => isset($call->args[0]) ? trim($call->args[0]) : null,
            'proc_open' => isset($call->args[0]) ? trim($call->args[0]) : null,
            default => null,
        };
    }

    private function expressionHasDangerousPattern(string $expression): bool
    {
        foreach (self::DANGEROUS_ARG_PATTERNS as $pattern) {
            if (preg_match($pattern, $expression)) {
                return true;
            }
        }

        return false;
    }

    private function resolveSafeCallbackAssignmentBeforeLine(AnalysisObject $ao, string $expression, int $line): ?\Wpma\Models\VariableAssignment
    {
        $trimmed = trim($expression);
        if ($trimmed === '' || $this->isCompoundCallbackExpression($trimmed)) {
            return null;
        }

        if (preg_match('/\$[a-zA-Z_][\w]*/', $trimmed, $m) !== 1) {
            return null;
        }

        $assignment = $ao->findAssignmentForVariableBeforeLine($m[0], $line);
        if ($assignment === null) {
            return null;
        }

        return $this->assignmentExpressionHasUnsupportedCallbackMemberAccess($assignment->expression)
            ? null
            : $assignment;
    }

    private function isCompoundCallbackExpression(string $expression): bool
    {
        return preg_match('/->|::\$|\[[^\]]*\]/', $expression) === 1;
    }

    private function assignmentExpressionHasUnsupportedCallbackMemberAccess(string $expression): bool
    {
        $trimmed = trim($expression);
        if (preg_match('/\$_(POST|GET|REQUEST|COOKIE|SERVER|FILES)\s*\[[^\]]+\]/', $trimmed) === 1) {
            return false;
        }

        return $this->isCompoundCallbackExpression($trimmed);
    }

    private function assignmentContainsDangerousPattern(\Wpma\Models\VariableAssignment $assignment): bool
    {
        if ($this->expressionHasDangerousPattern($assignment->expression)) {
            return true;
        }

        foreach ($assignment->functionNames as $functionName) {
            if (in_array(strtolower($functionName), ['file_get_contents', 'base64_decode', 'gzinflate', 'gzdecode', 'str_rot13', 'hex2bin'], true)) {
                return true;
            }
        }

        return false;
    }

    private function isStaticCallbackTarget(string $expression): bool
    {
        $trimmed = trim($expression);
        if ($trimmed === '') {
            return false;
        }

        if (($trimmed[0] ?? '') === '$') {
            return false;
        }

        if (preg_match('/^[\'\"][^\'\"]+[\'\"]$/', $trimmed) === 1) {
            return true;
        }

        if (preg_match('/^[a-zA-Z_\\\\][a-zA-Z0-9_\\\\]*$/', $trimmed) === 1) {
            return true;
        }

        return preg_match('/^\[[^\]]+\]$/', $trimmed) === 1;
    }

    private function buildExplanation(string $func, string $reason, array $args): string
    {
        $argStr = !empty($args) ? ' Arguments seen: ' . implode(', ', array_slice($args, 0, 2)) . '.' : '';
        return "The function `{$func}` can execute arbitrary code or commands when given attacker-controlled input. {$reason}.{$argStr} "
             . "Legitimate WordPress code uses this function for hooks and callbacks — confidence depends on argument source.";
    }

    private function detectSuspiciousWpAdministratorCreation(AnalysisObject $ao): ?Finding
    {
        $candidates = [];

        foreach ($ao->functionCalls as $call) {
            $lower = strtolower($call->name);

            if ($lower === 'wp_create_user' || $lower === 'wp_insert_user') {
                $candidates[] = [
                    'kind' => 'user_creation',
                    'call' => $call,
                ];
                continue;
            }

            if ($lower === 'set_role' && $this->argsGrantAdministrator($call->args)) {
                $candidates[] = [
                    'kind' => 'role_promotion',
                    'call' => $call,
                ];
                continue;
            }

            if (($lower === 'add_cap' || $lower === 'update_user_meta') && $this->argsGrantAdministratorCapability($call->args)) {
                $candidates[] = [
                    'kind' => 'capability_promotion',
                    'call' => $call,
                ];
            }
        }

        foreach ($candidates as $candidate) {
            $triggerCall = $candidate['call'];
            $context = $this->buildBack005OperationContext($ao, $triggerCall);
            $promotesToAdmin = $candidate['kind'] !== 'user_creation';
            $createsUserFromInput = $candidate['kind'] === 'user_creation' && $this->operationArgsContainUserInput($ao, $triggerCall);
            $hasDangerousInput = $this->operationHasDangerousInput($ao, $triggerCall, $context);
            $hasExecution = $this->operationHasExecution($context);
            $hasDynamicDispatch = $this->operationHasDynamicDispatch($ao, $triggerCall, $context);
            $hasEncodedPayload = $this->operationHasEncodedPayload($context);
            $hasElevatedObfuscation = $this->operationHasElevatedObfuscation($context);
            $hasHiddenAccountIndicator = $this->operationHasHiddenAdminIndicator($context);

            $hasStrongCorroboration = $hasExecution
                || ($hasDangerousInput && $promotesToAdmin)
                || ($createsUserFromInput && $promotesToAdmin)
                || ($hasEncodedPayload && ($promotesToAdmin || $createsUserFromInput))
                || ($hasElevatedObfuscation && ($promotesToAdmin || $createsUserFromInput))
                || ($hasDynamicDispatch && ($promotesToAdmin || $createsUserFromInput))
                || ($hasHiddenAccountIndicator && ($promotesToAdmin || $createsUserFromInput));

            if (!$hasStrongCorroboration) {
                continue;
            }

            $signals = [];
            if ($createsUserFromInput) {
                $signals[] = 'user creation is driven by attacker-controlled input';
            }
            if ($promotesToAdmin) {
                $signals[] = 'grants administrator role or capability';
            }
            if ($hasHiddenAccountIndicator) {
                $signals[] = 'contains hidden or stealth account indicators';
            }
            if ($hasExecution) {
                $signals[] = 'contains direct code-execution capability';
            }
            if ($hasDynamicDispatch) {
                $signals[] = 'uses dynamic dispatch';
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

            $severity = ($hasExecution || ($createsUserFromInput && $promotesToAdmin))
                ? Severity::CRITICAL
                : Severity::HIGH;
            $confidence = count($signals) >= 3 ? Confidence::HIGH : Confidence::MEDIUM;

            return Finding::create([
                'ruleId'      => 'BACK-005',
                'title'       => 'Suspicious WordPress administrator creation',
                'filePath'    => $ao->meta->filePath,
                'line'        => $triggerCall->line,
                'severity'    => $severity,
                'confidence'  => $confidence,
                'category'    => DetectionCategory::BACKDOOR,
                'description' => 'This file programmatically creates or promotes a WordPress user toward administrator access with additional suspicious corroboration.',
                'explanation' => 'WordPress user-creation and role APIs are legitimate in normal registration or admin-management flows, so they are not flagged on their own. This finding is emitted only when a specific administrator-creation or promotion operation is correlated with stronger suspicious signals in that same behavioral flow, such as attacker-controlled input, stealth account indicators, obfuscation, dynamic execution, or payload-like behavior. Correlated signals: ' . implode('; ', $signals) . '.',
                'remediation' => 'Review this code path carefully. If it creates or promotes users outside an expected authenticated admin workflow, remove it immediately and audit WordPress administrator accounts, user_meta capabilities, and recent login activity.',
                'evidence'    => [
                    $this->makeEvidence(
                        $triggerCall->line,
                        $this->snippet($ao->rawContent, $triggerCall->line),
                        'Administrator creation/promotion API use: ' . $triggerCall->name . '()',
                    ),
                ],
                'tags'        => ['backdoor', 'wordpress-admin', 'user-creation', 'privilege-escalation'],
            ]);
        }

        return null;
    }

    private function buildBack005OperationContext(AnalysisObject $ao, FunctionCall $triggerCall): ?array
    {
        $functionRanges = $this->buildSameFileFunctionBodyRanges($ao->tokens);
        foreach ($functionRanges as $range) {
            if ($triggerCall->line < $range['startLine'] || $triggerCall->line > $range['endLine']) {
                continue;
            }

            $bodyTokens = array_slice($ao->tokens, $range['startIndex'], $range['endIndex'] - $range['startIndex'] + 1);
            $bodyText = $this->tokensToString($bodyTokens, 0, count($bodyTokens) - 1);
            $functionNames = [];

            foreach ($bodyTokens as $token) {
                if ($token->id === \T_STRING) {
                    $functionNames[] = strtolower($token->text);
                }
            }

            $range['bodyText'] = $bodyText;
            $range['functionNames'] = $functionNames;

            return $range;
        }

        return null;
    }

    private function operationArgsContainUserInput(AnalysisObject $ao, FunctionCall $triggerCall): bool
    {
        if ($this->argsContainUserInput($triggerCall->args)) {
            return true;
        }

        $assignment = $this->resolveRelevantAssignmentFromArgsBeforeLine($ao, $triggerCall->args, $triggerCall->line);
        return $assignment !== null && $assignment->usesUserInput;
    }

    private function operationHasDangerousInput(AnalysisObject $ao, FunctionCall $triggerCall, ?array $context): bool
    {
        if ($this->operationArgsContainUserInput($ao, $triggerCall)) {
            return true;
        }

        return $this->contextContainsPattern($ao, $context, '/\$_(POST|GET|REQUEST|COOKIE|SERVER|FILES)\b/');
    }

    private function operationHasExecution(?array $context): bool
    {
        if ($context === null) {
            return false;
        }

        return preg_match('/\b(eval|assert)\s*\(/i', $context['bodyText']) === 1;
    }

    private function operationHasDynamicDispatch(AnalysisObject $ao, FunctionCall $triggerCall, ?array $context): bool
    {
        if ($triggerCall->isDynamic) {
            return true;
        }

        $assignment = $this->resolveRelevantAssignmentFromArgsBeforeLine($ao, $triggerCall->args, $triggerCall->line);
        if ($assignment !== null && array_intersect(
            array_map('strtolower', $assignment->functionNames),
            ['call_user_func', 'call_user_func_array']
        ) !== []) {
            return true;
        }

        if ($context === null) {
            return false;
        }

        return preg_match('/\b(call_user_func|call_user_func_array)\s*\(/i', $context['bodyText']) === 1;
    }

    private function operationHasEncodedPayload(?array $context): bool
    {
        if ($context === null) {
            return false;
        }

        return $this->bodyContainsEncodedBlob($context['bodyText']);
    }

    private function operationHasElevatedObfuscation(?array $context): bool
    {
        if ($context === null) {
            return false;
        }

        return $this->computeCallbackObfuscationScore(
            $context['bodyText'],
            $context['functionNames'],
            $this->bodyContainsEncodedBlob($context['bodyText']),
            preg_match('/\b(eval|assert)\s*\(/i', $context['bodyText']) === 1,
        ) > 0.35;
    }

    private function operationHasHiddenAdminIndicator(?array $context): bool
    {
        if ($context === null) {
            return false;
        }

        $lower = strtolower($context['bodyText']);
        if (str_contains($lower, 'user_register')) {
            return false;
        }

        return preg_match('/hidden|stealth|backdoor|secret|bypass|cloak/', $lower) === 1;
    }

    private function resolveRelevantAssignmentFromArgsBeforeLine(AnalysisObject $ao, array $args, int $line): ?\Wpma\Models\VariableAssignment
    {
        foreach ($args as $arg) {
            if (preg_match('/\$[a-zA-Z_][\w]*/', $arg, $m) === 1) {
                $assignment = $ao->findAssignmentForVariableBeforeLine($m[0], $line);
                if ($assignment !== null) {
                    return $assignment;
                }
            }
        }

        return null;
    }

    private function contextContainsPattern(AnalysisObject $ao, ?array $context, string $pattern): bool
    {
        if ($context === null) {
            return false;
        }

        return preg_match($pattern, $context['bodyText']) === 1;
    }

    private function buildRemediation(string $func, Severity $severity): string
    {
        if ($severity === Severity::CRITICAL || $severity === Severity::HIGH) {
            return "Inspect the argument passed to `{$func}`. If it derives from user input, request parameters, or an encoded string, this is likely malicious. Remove or replace immediately.";
        }
        return "Review this `{$func}` call. If it is a standard WP hook callback with a trusted function name, it is likely legitimate.";
    }

    private function detectMaliciousRedirectOrCredentialTheft(AnalysisObject $ao): ?Finding
    {
        $currentFile = (string) ($ao->meta->filePath ?? '');

        foreach ($ao->functionCalls as $call) {
            $lower = strtolower($call->name);

            if ($lower === 'header' && $this->looksLikeRedirectHeaderCall($call->args)) {
                $finding = $this->detectBack007RedirectCall($ao, $call, $currentFile);
                if ($finding !== null) {
                    return $finding;
                }
                continue;
            }

            if (($lower === 'wp_redirect' || $lower === 'wp_safe_redirect') && !empty($call->args)) {
                $finding = $this->detectBack007RedirectCall($ao, $call, $currentFile);
                if ($finding !== null) {
                    return $finding;
                }
                continue;
            }

            if (in_array($lower, ['wp_remote_post', 'wp_remote_get', 'curl_exec', 'fsockopen', 'stream_socket_client', 'file_get_contents', 'fopen', 'mail'], true)) {
                $finding = $this->detectBack007CredentialExfiltrationCall($ao, $call, $currentFile);
                if ($finding !== null) {
                    return $finding;
                }
            }
        }

        return null;
    }

    private function detectBack007RedirectCall(AnalysisObject $ao, FunctionCall $call, string $currentFile): ?Finding
    {
        $targetExpression = $this->extractRedirectTargetExpression($call);
        if ($targetExpression === null || trim($targetExpression) === '') {
            return null;
        }

        $targetAssignment = $this->resolveRelevantAssignmentFromArgsBeforeLine($ao, [$targetExpression], $call->line);
        $targetUsesDangerousInput = $this->redirectTargetHasDirectUserInputControl($ao, $call, $targetExpression, $call->line, []);
        $targetUsesRemoteDestination = $this->expressionHasRemoteContent($targetExpression)
            || ($targetAssignment !== null && $this->assignmentContainsRemoteContent($targetAssignment));
        $targetUsesEncodedContent = $this->expressionContainsDecodeFunction($targetExpression)
            || ($targetAssignment !== null && $this->assignmentContainsDecodeFunction($targetAssignment));
        $context = $this->buildBack005OperationContext($ao, $call);
        $hasConditionalContext = $context !== null && preg_match('/\bif\s*\(|\?:/i', $context['bodyText']) === 1;

        if (!$targetUsesDangerousInput) {
            return null;
        }

        $signals = ['uses PHP redirect behavior'];
        $signals[] = 'redirect target is attacker-controlled';
        if ($targetUsesRemoteDestination) {
            $signals[] = 'redirect target resolves to a remote destination';
        }
        if ($targetUsesEncodedContent) {
            $signals[] = 'redirect target uses encoded or decoded content';
        }
        if ($hasConditionalContext) {
            $signals[] = 'redirect occurs in a conditional flow';
        }

        return Finding::create([
            'ruleId'      => 'BACK-007',
            'title'       => 'Malicious redirect or credential-theft behaviour',
            'filePath'    => $currentFile,
            'line'        => $call->line,
            'severity'    => $targetUsesRemoteDestination ? Severity::CRITICAL : Severity::HIGH,
            'confidence'  => count($signals) >= 3 ? Confidence::HIGH : Confidence::MEDIUM,
            'category'    => DetectionCategory::REDIRECT,
            'description' => 'This file performs suspicious redirect behavior with correlated malicious indicators tied to the redirect target.',
            'explanation' => 'Redirects are legitimate in many applications and are not flagged on their own. This finding is emitted only when the specific redirect target itself, or a supported bare-variable provenance chain for that target, is attacker-controlled. Correlated signals: ' . implode('; ', $signals) . '.',
            'remediation' => 'Inspect this redirect target carefully. If attacker-controlled input can direct users to arbitrary or external locations, constrain the destination to trusted internal paths or a strict allowlist.',
            'evidence'    => [
                $this->makeEvidence(
                    $call->line,
                    $this->snippet($ao->rawContent, $call->line),
                    'Redirect behavior: ' . $call->name . '()'
                ),
            ],
            'iocs'        => $this->extractRelevantRedirectTargetIocs($ao->iocs, $currentFile, $targetExpression, $targetAssignment, $context),
            'tags'        => ['backdoor', 'redirect', 'phishing'],
        ]);
    }

    private function detectBack007CredentialExfiltrationCall(AnalysisObject $ao, FunctionCall $call, string $currentFile): ?Finding
    {
        $relevantAssignment = $this->resolveRelevantAssignmentFromArgsBeforeLine($ao, $call->args, $call->line);
        $context = $this->buildBack005OperationContext($ao, $call);
        $joinedArgs = implode(' ', $call->args);
        $usesDangerousInput = $this->argsContainUserInput($call->args)
            || ($relevantAssignment !== null && $relevantAssignment->usesUserInput)
            || ($context !== null && preg_match('/\$_(POST|GET|REQUEST|COOKIE|SERVER|FILES)\b/', $context['bodyText']) === 1);
        $usesRemoteDestination = $this->argsContainRemoteContent($call->args)
            || ($relevantAssignment !== null && $this->assignmentContainsRemoteContent($relevantAssignment));
        $hasCredentialFields = preg_match('/(pass(word)?|pwd|login|user(name)?|email|credential)/i', $joinedArgs) === 1
            || ($relevantAssignment !== null && preg_match('/(pass(word)?|pwd|login|user(name)?|email|credential)/i', $relevantAssignment->expression) === 1)
            || ($context !== null && (
                preg_match('/\$_POST\s*\[[^\]]*(pass(word)?|pwd|login|user(name)?|email|credential)[^\]]*\]/i', $context['bodyText']) === 1
                || preg_match('/[\'\"](?:pass(word)?|pwd|login|user(name)?|email|credential)[\'\"]\s*=>/i', $context['bodyText']) === 1
                || preg_match('/\$_POST\s*\[[^\]]+\].*[\r\n\s\S]{0,400}[\'\"](?:pass(word)?|pwd|login|user(name)?|email|credential)[\'\"]\s*=>/i', $context['bodyText']) === 1
            ));

        if (!($hasCredentialFields && $usesDangerousInput && $usesRemoteDestination)) {
            return null;
        }

        $signals = [
            'captures credential-like POST data and transmits it remotely',
            'specific outbound operation uses attacker-controlled input',
            'specific outbound operation targets a remote destination',
        ];

        return Finding::create([
            'ruleId'      => 'BACK-007',
            'title'       => 'Malicious redirect or credential-theft behaviour',
            'filePath'    => $currentFile,
            'line'        => $call->line,
            'severity'    => Severity::CRITICAL,
            'confidence'  => Confidence::HIGH,
            'category'    => DetectionCategory::CREDENTIAL_STEAL,
            'description' => 'This file performs suspicious credential exfiltration behavior with a proven relationship between credential-like input and a specific outbound transmission.',
            'explanation' => 'Credential handling is not flagged on its own. This finding is emitted only when the same outbound operation both processes credential-like POST data and transmits attacker-controlled input to a remote destination. Correlated signals: ' . implode('; ', $signals) . '.',
            'remediation' => 'Inspect this outbound transmission immediately. Remove any unexpected remote credential submission and audit authentication flows, form handlers, and outbound requests for phishing or exfiltration behavior.',
            'evidence'    => [
                $this->makeEvidence(
                    $call->line,
                    $this->snippet($ao->rawContent, $call->line),
                    'Credential transmission or remote outbound behavior: ' . $call->name . '()'
                ),
            ],
            'iocs'        => $this->extractRelevantInjectionIocsForLineRange($ao->iocs, $currentFile, $context['startLine'] ?? $call->line, $context['endLine'] ?? $call->line),
            'tags'        => ['backdoor', 'credential-theft', 'phishing'],
        ]);
    }

    private function extractRedirectTargetExpression(FunctionCall $call): ?string
    {
        $lower = strtolower($call->name);
        if ($lower === 'header') {
            $first = trim($call->args[0] ?? '');
            if (preg_match('/^[\'\"]location\s*:\s*/i', $first) !== 1) {
                return null;
            }

            $target = preg_replace('/^[\'\"]location\s*:\s*/i', '', $first, 1);
            if ($target === null) {
                return null;
            }

            return preg_replace('/[\'\"]\s*\.\s*$/', '', trim($target));
        }

        if ($lower === 'wp_redirect' || $lower === 'wp_safe_redirect') {
            return isset($call->args[0]) ? trim($call->args[0]) : null;
        }

        return null;
    }

    private function expressionUsesUserInput(string $expression): bool
    {
        return preg_match('/\$_(POST|GET|REQUEST|COOKIE|SERVER|FILES)\b/', $expression) === 1;
    }

    private function redirectTargetHasDirectUserInputControl(AnalysisObject $ao, FunctionCall $call, string $expression, int $line, array $visited): bool
    {
        $trimmed = trim($expression);
        if ($trimmed === '') {
            return false;
        }

        if ($this->isDirectUserInputExpressionForRedirect($call, $trimmed)) {
            return true;
        }

        if (!preg_match('/^\$[a-zA-Z_][\w]*$/', $trimmed)) {
            return false;
        }

        $visitKey = $trimmed . ':' . $line;
        if (in_array($visitKey, $visited, true)) {
            return false;
        }
        $visited[] = $visitKey;

        $assignment = $ao->findAssignmentForVariableBeforeLine($trimmed, $line);
        if ($assignment === null) {
            return false;
        }

        return $this->redirectTargetHasDirectUserInputControl($ao, $call, $assignment->expression, $assignment->line - 1, $visited);
    }

    private function isDirectUserInputExpressionForRedirect(FunctionCall $call, string $expression): bool
    {
        $trimmed = trim($expression);
        $unwrapped = $this->unwrapRedirectExpression($trimmed);
        if ($unwrapped !== $trimmed) {
            return $this->isDirectUserInputExpressionForRedirect($call, $unwrapped);
        }

        if (preg_match('/^[\'\"]\s*\.\s*(.+)$/', $trimmed, $m) === 1) {
            return $this->isDirectUserInputExpressionForRedirect($call, $m[1]);
        }

        if (preg_match('/^(wp_unslash|urldecode|rawurldecode|trim|sanitize_text_field|esc_url_raw)\s*\((.*)\)$/i', $trimmed, $m) === 1) {
            return $this->isDirectUserInputExpressionForRedirect($call, $m[2]);
        }

        if (preg_match('/^(.+?)\s*\?\?\s*(null|[\'\"].*[\'\"]|\$[a-zA-Z_][\w]*)$/is', $trimmed, $m) === 1) {
            return $this->isDirectUserInputExpressionForRedirect($call, $m[1]);
        }

        if (preg_match('/^\$_(GET|POST|REQUEST)\s*(\[[^\]]+\])?$/', $trimmed) === 1) {
            return strtolower($call->name) !== 'wp_safe_redirect';
        }

        if (preg_match('/^\$_SERVER\s*(\[[^\]]+\])?$/', $trimmed) === 1) {
            return false;
        }

        if (preg_match('/^\$_(COOKIE|FILES)\s*(\[[^\]]+\])?$/', $trimmed) === 1) {
            return false;
        }

        return false;
    }

    private function unwrapRedirectExpression(string $expression): string
    {
        $trimmed = trim($expression);
        while (strlen($trimmed) >= 2 && $trimmed[0] === '(' && substr($trimmed, -1) === ')' && $this->redirectExpressionHasBalancedOuterParens($trimmed)) {
            $trimmed = trim(substr($trimmed, 1, -1));
        }

        return $trimmed;
    }

    private function redirectExpressionHasBalancedOuterParens(string $expression): bool
    {
        $depth = 0;
        $len = strlen($expression);

        for ($i = 0; $i < $len; $i++) {
            $ch = $expression[$i];
            if ($ch === '(') {
                $depth++;
            } elseif ($ch === ')') {
                $depth--;
                if ($depth === 0 && $i !== $len - 1) {
                    return false;
                }
                if ($depth < 0) {
                    return false;
                }
            }
        }

        return $depth === 0;
    }

    private function expressionHasRemoteContent(string $expression): bool
    {
        return preg_match('/https?:\/\/|wp_remote_get\s*\(|wp_remote_post\s*\(|file_get_contents\s*\(|curl_exec\s*\(|fsockopen\s*\(|stream_socket_client\s*\(|mail\s*\(/i', $expression) === 1;
    }

    private function expressionContainsDecodeFunction(string $expression): bool
    {
        return preg_match('/\b(base64_decode|gzinflate|gzdecode|gzuncompress|str_rot13|hex2bin|rawurldecode)\s*\(/i', $expression) === 1;
    }

    private function extractRelevantRedirectTargetIocs(array $iocs, string $currentFile, string $targetExpression, ?\Wpma\Models\VariableAssignment $targetAssignment, ?array $context): array
    {
        $matches = [];
        $relevantText = $targetExpression . ' ' . ($targetAssignment?->expression ?? '');
        $startLine = $targetAssignment?->line ?? ($context['startLine'] ?? 0);
        $endLine = $context['endLine'] ?? ($targetAssignment?->line ?? 0);

        foreach ($iocs as $ioc) {
            if ($ioc->filePath !== $currentFile) {
                continue;
            }

            if (($ioc->type->value !== 'url' && $ioc->type->value !== 'domain') || $ioc->isKnownWpService) {
                continue;
            }

            if ($startLine > 0 && $endLine > 0 && ($ioc->line < $startLine || $ioc->line > $endLine)) {
                continue;
            }

            if (!str_contains($relevantText, $ioc->value)) {
                continue;
            }

            $matches[] = $ioc;
        }

        return $matches;
    }

    private function detectSuspiciousWpHeadFooterInjection(AnalysisObject $ao): ?Finding
    {
        $currentFile = (string) ($ao->meta->filePath ?? '');

        foreach ($ao->functionCalls as $hookCall) {
            $lower = strtolower($hookCall->name);
            if (($lower !== 'add_action' && $lower !== 'add_filter') || !$this->argsReferenceWpHeadOrFooter($hookCall->args)) {
                continue;
            }

            $callbackRange = $this->resolveWpHeadFooterCallbackRange($ao, $hookCall);
            if ($callbackRange === null) {
                continue;
            }

            $localSignals = $this->analyzeWpHookCallbackSignals($ao, $callbackRange, $currentFile);
            $hasDangerousInput = $localSignals['hasDangerousInput'];
            $hasExecution = $localSignals['hasExecution'];
            $hasEncodedPayload = $localSignals['hasEncodedPayload'];
            $hasElevatedObfuscation = $localSignals['hasElevatedObfuscation'];
            $hasHiddenScriptIndicator = $localSignals['hasHiddenScriptIndicator'];
            $hasRemoteContent = $localSignals['hasRemoteContent'];
            $payloadIocs = $localSignals['payloadIocs'];

            $hasStrongCorroboration = $hasExecution
                || ($hasEncodedPayload && ($hasHiddenScriptIndicator || $hasRemoteContent || $hasDangerousInput))
                || ($hasDangerousInput && ($hasHiddenScriptIndicator || $hasRemoteContent))
                || ($hasElevatedObfuscation && ($hasHiddenScriptIndicator || $hasRemoteContent || $hasDangerousInput))
                || (!empty($payloadIocs) && ($hasHiddenScriptIndicator || $hasRemoteContent || $hasExecution));

            if (!$hasStrongCorroboration) {
                continue;
            }

            $signals = ['registers a wp_head/wp_footer hook'];
            $evidence = [
                $this->makeEvidence(
                    $hookCall->line,
                    $this->snippet($ao->rawContent, $hookCall->line),
                    'Hook registration: ' . $hookCall->name . '(' . implode(', ', array_slice($hookCall->args, 0, 2)) . ')',
                ),
                $this->makeEvidence(
                    $callbackRange['startLine'],
                    $this->snippet($ao->rawContent, $callbackRange['startLine']),
                    $callbackRange['type'] === 'named_function'
                        ? 'Resolved same-file callback body: ' . $callbackRange['name'] . '()'
                        : 'Resolved inline closure callback body',
                ),
            ];

            if ($hasHiddenScriptIndicator) {
                $signals[] = 'callback contains hidden script or iframe injection indicators';
            }
            if ($hasRemoteContent) {
                $signals[] = 'callback references remote content';
            }
            if ($hasDangerousInput) {
                $signals[] = 'callback uses attacker-controlled input';
            }
            if ($hasExecution) {
                $signals[] = 'callback contains direct code-execution capability';
            }
            if ($hasEncodedPayload) {
                $signals[] = 'callback contains encoded payload material';
            }
            if ($hasElevatedObfuscation) {
                $signals[] = sprintf('callback has elevated obfuscation score (%.2f)', $localSignals['obfuscationScore']);
            }
            if (!empty($payloadIocs)) {
                $signals[] = 'callback contains remote payload/network IOCs';
            }

            return Finding::create([
                'ruleId'      => 'BACK-006',
                'title'       => 'Suspicious wp_head/wp_footer injection',
                'filePath'    => $currentFile,
                'line'        => $hookCall->line,
                'severity'    => ($hasExecution || ($hasDangerousInput && ($hasHiddenScriptIndicator || $hasEncodedPayload))) ? Severity::CRITICAL : Severity::HIGH,
                'confidence'  => count($signals) >= 3 ? Confidence::HIGH : Confidence::MEDIUM,
                'category'    => DetectionCategory::JS_INJECTION,
                'description' => 'This file injects code through a WordPress wp_head/wp_footer hook with correlated suspicious payload or content-injection signals in the registered callback body.',
                'explanation' => 'Normal wp_head/wp_footer hook usage is common in WordPress and is not flagged by itself. This finding is emitted only when the resolved hook callback body contains stronger signals such as obfuscated payloads, hidden script or iframe injection, attacker-controlled content, remote payload references, or dynamic code-execution behavior. Correlated callback-local signals: ' . implode('; ', $signals) . '.',
                'remediation' => 'Inspect the registered wp_head/wp_footer callback and remove any unexpected injected markup, remote script loads, or obfuscated payload logic. Audit theme and plugin code for other front-end injection hooks.',
                'evidence'    => $evidence,
                'iocs'        => $payloadIocs,
                'tags'        => ['backdoor', 'wp-head', 'wp-footer', 'injection', 'front-end'],
            ]);
        }

        return null;
    }

    private function argsGrantAdministrator(array $args): bool
    {
        foreach ($args as $arg) {
            if ($this->isAdministratorValue($arg)) {
                return true;
            }
        }

        return false;
    }

    private function looksLikeRedirectHeaderCall(array $args): bool
    {
        if (empty($args)) {
            return false;
        }

        return preg_match('/^[\'\"]location\s*:/i', trim($args[0])) === 1;
    }

    private function resolveRelevantAssignmentFromArgs(AnalysisObject $ao, array $args): ?\Wpma\Models\VariableAssignment
    {
        foreach ($args as $arg) {
            if (preg_match('/\$[a-zA-Z_][\w]*/', $arg, $m) === 1) {
                $assignment = $ao->findAssignmentForVariable($m[0]);
                if ($assignment !== null) {
                    return $assignment;
                }
            }
        }

        return null;
    }

    private function argsContainRemoteContent(array $args): bool
    {
        $joined = implode(' ', $args);
        return preg_match('/https?:\/\/|wp_remote_get\s*\(|wp_remote_post\s*\(|file_get_contents\s*\(|curl_exec\s*\(|fsockopen\s*\(|stream_socket_client\s*\(|mail\s*\(/i', $joined) === 1;
    }

    private function assignmentContainsRemoteContent(\Wpma\Models\VariableAssignment $assignment): bool
    {
        if (preg_match('/https?:\/\//i', $assignment->expression) === 1) {
            return true;
        }

        foreach ($assignment->functionNames as $functionName) {
            if (in_array(strtolower($functionName), ['wp_remote_get', 'wp_remote_post', 'file_get_contents', 'curl_exec', 'fsockopen', 'stream_socket_client', 'mail'], true)) {
                return true;
            }
        }

        return false;
    }

    private function assignmentContainsDecodeFunction(\Wpma\Models\VariableAssignment $assignment): bool
    {
        foreach ($assignment->functionNames as $functionName) {
            if (in_array(strtolower($functionName), ['base64_decode', 'gzinflate', 'gzdecode', 'gzuncompress', 'str_rot13', 'hex2bin', 'rawurldecode'], true)) {
                return true;
            }
        }

        return false;
    }

    private function argsReferenceWpHeadOrFooter(array $args): bool
    {
        foreach ($args as $arg) {
            $normalized = strtolower(trim($arg, " \t\n\r\0\x0B'\""));
            if ($normalized === 'wp_head' || $normalized === 'wp_footer') {
                return true;
            }
        }

        return false;
    }

    private function resolveWpHeadFooterCallbackRange(AnalysisObject $ao, FunctionCall $hookCall): ?array
    {
        $hookCallTokens = $this->findHookCallTokenArguments($ao->tokens, $hookCall);
        if ($hookCallTokens === null || count($hookCallTokens) < 2) {
            return null;
        }

        $callbackArg = $hookCallTokens[1];
        $closureRange = $this->resolveInlineClosureRange($ao->tokens, $callbackArg['start'], $callbackArg['end']);
        if ($closureRange !== null) {
            return $closureRange;
        }

        $callbackName = $this->literalStringFromTokenRange($ao->tokens, $callbackArg['start'], $callbackArg['end']);
        if ($callbackName === null || preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*$/', $callbackName) !== 1) {
            return null;
        }

        $functionRanges = $this->buildSameFileFunctionBodyRanges($ao->tokens);
        return $functionRanges[strtolower($callbackName)] ?? null;
    }

    private function findHookCallTokenArguments(array $tokens, FunctionCall $hookCall): ?array
    {
        $count = count($tokens);
        $hookName = strtolower($hookCall->name);

        for ($i = 0; $i < $count; $i++) {
            $token = $tokens[$i];
            if ($token->id !== \T_STRING || strtolower($token->text) !== $hookName || $token->line !== $hookCall->line) {
                continue;
            }

            $openParen = $this->nextNonWhitespace($tokens, $i + 1);
            if ($openParen === null || $tokens[$openParen]->text !== '(') {
                continue;
            }

            $args = $this->collectCallArgumentRanges($tokens, $openParen);
            if (!empty($args) && $this->tokenRangeReferencesWpHeadOrFooter($tokens, $args[0]['start'], $args[0]['end'])) {
                return $args;
            }
        }

        return null;
    }

    private function collectCallArgumentRanges(array $tokens, int $openParenIndex): array
    {
        $args = [];
        $count = count($tokens);
        $argStart = $openParenIndex + 1;
        $parenDepth = 1;
        $bracketDepth = 0;
        $braceDepth = 0;

        for ($i = $openParenIndex + 1; $i < $count; $i++) {
            $text = $tokens[$i]->text;

            if ($text === '(') {
                $parenDepth++;
            } elseif ($text === ')') {
                $parenDepth--;
                if ($parenDepth === 0) {
                    $range = $this->trimTokenRange($tokens, $argStart, $i - 1);
                    if ($range !== null) {
                        $args[] = $range;
                    }
                    return $args;
                }
            } elseif ($text === '[') {
                $bracketDepth++;
            } elseif ($text === ']') {
                $bracketDepth = max(0, $bracketDepth - 1);
            } elseif ($text === '{') {
                $braceDepth++;
            } elseif ($text === '}') {
                $braceDepth = max(0, $braceDepth - 1);
            } elseif ($text === ',' && $parenDepth === 1 && $bracketDepth === 0 && $braceDepth === 0) {
                $range = $this->trimTokenRange($tokens, $argStart, $i - 1);
                if ($range !== null) {
                    $args[] = $range;
                }
                $argStart = $i + 1;
            }
        }

        return $args;
    }

    private function resolveInlineClosureRange(array $tokens, int $start, int $end): ?array
    {
        for ($i = $start; $i <= $end; $i++) {
            if (($tokens[$i]->id ?? null) !== \T_FUNCTION) {
                continue;
            }

            $nameOrParams = $this->nextNonWhitespace($tokens, $i + 1);
            if ($nameOrParams !== null && $tokens[$nameOrParams]->text === '&') {
                $nameOrParams = $this->nextNonWhitespace($tokens, $nameOrParams + 1);
            }

            if ($nameOrParams === null || $tokens[$nameOrParams]->id === \T_STRING) {
                continue;
            }

            $openBrace = $this->findFunctionOpeningBrace($tokens, $i + 1, $end);
            if ($openBrace === null) {
                continue;
            }

            $closeBrace = $this->findMatchingBrace($tokens, $openBrace, $end);
            if ($closeBrace === null) {
                continue;
            }

            return [
                'type' => 'inline_closure',
                'name' => 'closure',
                'startIndex' => $openBrace + 1,
                'endIndex' => $closeBrace - 1,
                'startLine' => $tokens[$openBrace]->line,
                'endLine' => $tokens[$closeBrace]->line,
            ];
        }

        return null;
    }

    private function buildSameFileFunctionBodyRanges(array $tokens): array
    {
        $functions = [];
        $classLikeRanges = $this->buildClassLikeBodyRanges($tokens);
        $count = count($tokens);

        for ($i = 0; $i < $count; $i++) {
            if (($tokens[$i]->id ?? null) !== \T_FUNCTION || $this->tokenIndexInRanges($i, $classLikeRanges)) {
                continue;
            }

            $nameIndex = $this->nextNonWhitespace($tokens, $i + 1);
            if ($nameIndex !== null && $tokens[$nameIndex]->text === '&') {
                $nameIndex = $this->nextNonWhitespace($tokens, $nameIndex + 1);
            }

            if ($nameIndex === null || $tokens[$nameIndex]->id !== \T_STRING) {
                continue;
            }

            $openBrace = $this->findFunctionOpeningBrace($tokens, $nameIndex + 1, $count - 1);
            if ($openBrace === null) {
                continue;
            }

            $closeBrace = $this->findMatchingBrace($tokens, $openBrace, $count - 1);
            if ($closeBrace === null) {
                continue;
            }

            $functions[strtolower($tokens[$nameIndex]->text)] = [
                'type' => 'named_function',
                'name' => $tokens[$nameIndex]->text,
                'startIndex' => $openBrace + 1,
                'endIndex' => $closeBrace - 1,
                'startLine' => $tokens[$openBrace]->line,
                'endLine' => $tokens[$closeBrace]->line,
            ];

            $i = $closeBrace;
        }

        return $functions;
    }

    private function buildClassLikeBodyRanges(array $tokens): array
    {
        $ranges = [];
        $count = count($tokens);
        $classLikeTokenIds = [\T_CLASS, \T_INTERFACE, \T_TRAIT];

        for ($i = 0; $i < $count; $i++) {
            if (!in_array($tokens[$i]->id, $classLikeTokenIds, true)) {
                continue;
            }

            $openBrace = null;
            for ($j = $i + 1; $j < $count; $j++) {
                if ($tokens[$j]->text === '{') {
                    $openBrace = $j;
                    break;
                }
                if ($tokens[$j]->text === ';') {
                    break;
                }
            }

            if ($openBrace === null) {
                continue;
            }

            $closeBrace = $this->findMatchingBrace($tokens, $openBrace, $count - 1);
            if ($closeBrace === null) {
                continue;
            }

            $ranges[] = ['start' => $openBrace, 'end' => $closeBrace];
            $i = $closeBrace;
        }

        return $ranges;
    }

    private function findFunctionOpeningBrace(array $tokens, int $start, int $end): ?int
    {
        $parenDepth = 0;
        $bracketDepth = 0;

        for ($i = $start; $i <= $end; $i++) {
            $text = $tokens[$i]->text;
            if ($text === '(') {
                $parenDepth++;
            } elseif ($text === ')') {
                $parenDepth = max(0, $parenDepth - 1);
            } elseif ($text === '[') {
                $bracketDepth++;
            } elseif ($text === ']') {
                $bracketDepth = max(0, $bracketDepth - 1);
            } elseif ($text === '{' && $parenDepth === 0 && $bracketDepth === 0) {
                return $i;
            } elseif ($text === ';' && $parenDepth === 0 && $bracketDepth === 0) {
                return null;
            }
        }

        return null;
    }

    private function findMatchingBrace(array $tokens, int $openBraceIndex, int $end): ?int
    {
        $depth = 0;
        for ($i = $openBraceIndex; $i <= $end; $i++) {
            if ($tokens[$i]->text === '{') {
                $depth++;
            } elseif ($tokens[$i]->text === '}') {
                $depth--;
                if ($depth === 0) {
                    return $i;
                }
            }
        }

        return null;
    }

    private function analyzeWpHookCallbackSignals(AnalysisObject $ao, array $range, string $currentFile): array
    {
        $bodyTokens = array_slice($ao->tokens, $range['startIndex'], $range['endIndex'] - $range['startIndex'] + 1);
        $bodyText = $this->tokensToString($bodyTokens, 0, count($bodyTokens) - 1);
        $functionNames = [];
        $hasDangerousInput = preg_match('/\$_(POST|GET|REQUEST|COOKIE|SERVER|FILES)\b/', $bodyText) === 1;
        $hasExecution = false;
        $hasEncodedPayload = $this->bodyContainsEncodedBlob($bodyText);
        $hasRemoteContent = preg_match('/https?:\/\//i', $bodyText) === 1;

        foreach ($bodyTokens as $token) {
            if ($token->id === \T_VARIABLE && in_array($token->text, ['$_POST', '$_GET', '$_REQUEST', '$_COOKIE', '$_SERVER', '$_FILES'], true)) {
                $hasDangerousInput = true;
            }

            if ($token->id === \T_EVAL) {
                $hasExecution = true;
            }

            if ($token->id === \T_STRING) {
                $lower = strtolower($token->text);
                $functionNames[] = $lower;

                if ($lower === 'eval' || $lower === 'assert') {
                    $hasExecution = true;
                }

                if (in_array($lower, ['base64_decode', 'base64_encode', 'gzinflate', 'gzdecode', 'gzuncompress', 'str_rot13', 'pack', 'unpack', 'hex2bin', 'rawurldecode', 'urldecode', 'convert_uuencode', 'convert_uudecode'], true)) {
                    $hasEncodedPayload = true;
                }

                if (in_array($lower, ['curl_init', 'curl_exec', 'curl_setopt', 'fsockopen', 'stream_socket_client', 'file_get_contents', 'fopen', 'socket_create', 'socket_connect', 'wp_remote_get', 'wp_remote_post'], true)) {
                    $hasRemoteContent = true;
                }
            }
        }

        $obfuscationScore = $this->computeCallbackObfuscationScore($bodyText, $functionNames, $hasEncodedPayload, $hasExecution);

        return [
            'hasDangerousInput' => $hasDangerousInput,
            'hasExecution' => $hasExecution,
            'hasEncodedPayload' => $hasEncodedPayload,
            'hasElevatedObfuscation' => $obfuscationScore > 0.35,
            'obfuscationScore' => $obfuscationScore,
            'hasHiddenScriptIndicator' => preg_match('/<script|<iframe|display\s*:\s*none|visibility\s*:\s*hidden|position\s*:\s*absolute|opacity\s*:\s*0|document\.write|fromCharCode|base64_decode|gzinflate|atob\s*\(/i', $bodyText) === 1,
            'hasRemoteContent' => $hasRemoteContent,
            'payloadIocs' => $this->extractRelevantInjectionIocsForLineRange($ao->iocs, $currentFile, $range['startLine'], $range['endLine']),
        ];
    }

    private function computeCallbackObfuscationScore(string $bodyText, array $functionNames, bool $hasEncodedPayload, bool $hasExecution): float
    {
        $score = 0.0;
        $obfuscationFunctions = ['base64_decode', 'gzinflate', 'gzdecode', 'gzuncompress', 'str_rot13', 'hex2bin', 'pack', 'convert_uuencode', 'convert_uudecode'];
        $obfuscationFunctionCount = 0;

        foreach ($functionNames as $functionName) {
            if (in_array($functionName, $obfuscationFunctions, true)) {
                $obfuscationFunctionCount++;
            }
        }

        if ($obfuscationFunctionCount > 0 && ($hasEncodedPayload || $hasExecution)) {
            $score += min($obfuscationFunctionCount * 0.2, 0.5);
        } elseif ($obfuscationFunctionCount >= 5) {
            $score += min(($obfuscationFunctionCount - 4) * 0.1, 0.3);
        }

        if ($hasEncodedPayload) {
            $score += 0.15;
        }

        if ($hasExecution) {
            $score += 0.3;
        }

        if (preg_match('/\$\$[a-zA-Z_]\w*/', $bodyText) === 1) {
            $score += 0.15;
        }

        $hexEscapes = preg_match_all('/\\\\x[0-9a-fA-F]{2}/', $bodyText);
        if ($hexEscapes > 20) {
            $score += min($hexEscapes * 0.005, 0.25);
        }

        $chrCount = substr_count(strtolower($bodyText), 'chr(');
        if ($chrCount > 10) {
            $score += min($chrCount * 0.01, 0.2);
        }

        return round(min($score, 1.0), 4);
    }

    private function bodyContainsEncodedBlob(string $bodyText): bool
    {
        if (preg_match('/[A-Za-z0-9+\/]{100,}={0,2}/', $bodyText, $match) === 1) {
            return str_contains($match[0], '+') || str_contains($match[0], '/') || str_ends_with($match[0], '=');
        }

        return preg_match('/[0-9a-fA-F]{100,}/', $bodyText) === 1;
    }

    private function tokenRangeReferencesWpHeadOrFooter(array $tokens, int $start, int $end): bool
    {
        $literal = $this->literalStringFromTokenRange($tokens, $start, $end);
        return $literal === 'wp_head' || $literal === 'wp_footer';
    }

    private function literalStringFromTokenRange(array $tokens, int $start, int $end): ?string
    {
        $range = $this->trimTokenRange($tokens, $start, $end);
        if ($range === null || $range['start'] !== $range['end']) {
            return null;
        }

        $token = $tokens[$range['start']];
        if ($token->id !== \T_CONSTANT_ENCAPSED_STRING || strlen($token->text) < 2) {
            return null;
        }

        return trim($token->text, "'\"");
    }

    private function trimTokenRange(array $tokens, int $start, int $end): ?array
    {
        while ($start <= $end && $this->isIgnorableToken($tokens[$start]->id)) {
            $start++;
        }

        while ($end >= $start && $this->isIgnorableToken($tokens[$end]->id)) {
            $end--;
        }

        if ($start > $end) {
            return null;
        }

        return ['start' => $start, 'end' => $end];
    }

    private function isIgnorableToken(int $tokenId): bool
    {
        return $tokenId === \T_WHITESPACE || $tokenId === \T_COMMENT || $tokenId === \T_DOC_COMMENT;
    }

    private function nextNonWhitespace(array $tokens, int $from): ?int
    {
        $count = count($tokens);
        for ($i = $from; $i < $count; $i++) {
            if (!$this->isIgnorableToken($tokens[$i]->id)) {
                return $i;
            }
        }

        return null;
    }

    private function tokensToString(array $tokens, int $start, int $end): string
    {
        $text = '';
        for ($i = $start; $i <= $end; $i++) {
            $text .= $tokens[$i]->text ?? '';
        }

        return $text;
    }

    private function tokenIndexInRanges(int $index, array $ranges): bool
    {
        foreach ($ranges as $range) {
            if ($index >= $range['start'] && $index <= $range['end']) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array $iocs
     * @return array
     */
    private function extractRelevantInjectionIocsForLineRange(array $iocs, string $currentFile, int $startLine, int $endLine): array
    {
        $matches = [];

        foreach ($iocs as $ioc) {
            if ($ioc->filePath !== $currentFile || $ioc->line < $startLine || $ioc->line > $endLine) {
                continue;
            }

            $type = $ioc->type->value;
            if ($type === 'url' || $type === 'domain' || $ioc->isConfirmedMalicious) {
                $matches[] = $ioc;
            }
        }

        return $matches;
    }

    /**
     * @param array $iocs
     * @return array
     */
    private function extractRelevantInjectionIocs(array $iocs, string $currentFile): array
    {
        $matches = [];

        foreach ($iocs as $ioc) {
            if ($ioc->filePath !== $currentFile) {
                continue;
            }

            $type = $ioc->type->value;
            if ($type === 'url' || $type === 'domain' || $ioc->isConfirmedMalicious) {
                $matches[] = $ioc;
            }
        }

        return $matches;
    }

    private function argsGrantAdministratorCapability(array $args): bool
    {
        $joined = strtolower(implode(' ', $args));

        return str_contains($joined, 'administrator')
            || str_contains($joined, 'wp_capabilities')
            || preg_match('/[\'"]manage_options[\'"]/', $joined) === 1
            || preg_match('/[\'"]activate_plugins[\'"]/', $joined) === 1
            || preg_match('/[\'"]edit_users[\'"]/', $joined) === 1
            || preg_match('/[\'"]create_users[\'"]/', $joined) === 1
            || preg_match('/[\'"]promote_users[\'"]/', $joined) === 1;
    }

    private function argsContainUserInput(array $args): bool
    {
        return preg_match('/\$_(POST|GET|REQUEST|COOKIE|SERVER|FILES)\b/', implode(' ', $args)) === 1;
    }

    private function hasAdministratorLiteral(AnalysisObject $ao): bool
    {
        foreach ($ao->strings as $string) {
            if ($this->isAdministratorValue($string->value)) {
                return true;
            }
        }

        return false;
    }

    private function hasHiddenAdminIndicator(AnalysisObject $ao): bool
    {
        $lower = strtolower($ao->rawContent);

        return str_contains($lower, 'user_register')
            ? false
            : preg_match('/hidden|stealth|backdoor|secret|bypass|cloak/', $lower) === 1;
    }

    private function isAdministratorValue(string $value): bool
    {
        $normalized = strtolower(trim($value, " \t\n\r\0\x0B'\""));

        return $normalized === 'administrator'
            || $normalized === 'admin';
    }

    /**
     * Detect backtick shell execution in executable-only PHP source.
     * The source has already had comments and string literals replaced with spaces,
     * so SQL backtick identifiers and markdown backticks will NOT match here.
     */
    private function detectBacktick(string $execOnly, string $file, bool $hasUserInput, array &$findings): void
    {
        if (!str_contains($execOnly, '<?php') && !str_contains($execOnly, '<?=')) {
            return;
        }

        // Pattern: assignment or expression with backtick command
        // Must contain at least one space/slash/pipe (real commands have these)
        // Short backticks (<4 chars) are likely noise
        if (!preg_match_all('/`([^`\n]{4,80})`/', $execOnly, $matches, PREG_OFFSET_CAPTURE)) {
            return;
        }

        $reported = [];
        foreach ($matches[0] as $idx => $match) {
            $inner = $matches[1][$idx][0];

            // Must look like a shell command: contains space, slash, or pipe
            if (!preg_match('/[\s\/\|\&;>]/', $inner)) {
                continue;
            }

            // Skip if it resembles a PHP method/property (false positive from code gen)
            if (preg_match('/^[\$\w]+->|^new\s|^\w+::|^function\s/', $inner)) {
                continue;
            }

            $line = substr_count(substr($execOnly, 0, $match[1]), "\n") + 1;
            if (isset($reported[$line])) {
                continue;
            }
            $reported[$line] = true;

            $severity   = $hasUserInput ? Severity::HIGH : Severity::MEDIUM;
            $confidence = Confidence::MEDIUM;

            $findings[] = Finding::create([
                'ruleId'      => 'BACK-002',
                'title'       => 'Backtick Shell Execution Operator',
                'filePath'    => $file,
                'line'        => $line,
                'severity'    => $severity,
                'confidence'  => $confidence,
                'category'    => DetectionCategory::BACKDOOR,
                'description' => "PHP backtick operator executing shell command: `{$inner}`",
                'explanation' => 'The backtick operator executes shell commands identical to shell_exec(). '
                               . 'This detection runs only on executable PHP code — comments and string literals are excluded.',
                'remediation' => 'Verify this is intentional. Replace with shell_exec() for clarity. '
                               . 'If not authored by you, remove immediately.',
                'evidence'    => [$this->makeEvidence($line, $match[0], 'Backtick shell operator')],
                'tags'        => ['backdoor', 'shell'],
            ]);
        }
    }

    /**
     * Detect preg_replace() with /e modifier in executable-only PHP source.
     */
    private function detectPregReplaceE(string $execOnly, string $file, array &$findings): void
    {
        if (!preg_match_all(
            '#preg_replace\s*\(\s*[\'"][^"\']{0,50}/e[\'"]#i',
            $execOnly, $matches, PREG_OFFSET_CAPTURE
        )) {
            return;
        }

        foreach ($matches[0] as $match) {
            $line = substr_count(substr($execOnly, 0, $match[1]), "\n") + 1;

            $findings[] = Finding::create([
                'ruleId'      => 'BACK-003',
                'title'       => 'preg_replace() /e Modifier — Code Execution',
                'filePath'    => $file,
                'line'        => $line,
                'severity'    => Severity::CRITICAL,
                'confidence'  => Confidence::HIGH,
                'category'    => DetectionCategory::BACKDOOR,
                'description' => 'preg_replace() with /e modifier evaluates the replacement as PHP code.',
                'explanation' => 'The /e modifier was removed in PHP 7 because it allows arbitrary code execution. '
                               . 'Its presence in modern PHP code is almost always malicious.',
                'remediation' => 'Remove this call. Replace with preg_replace_callback() if legitimate.',
                'evidence'    => [$this->makeEvidence($line, $match[0], 'preg_replace /e pattern')],
                'tags'        => ['backdoor', 'preg-replace-e'],
            ]);
        }
    }

    /**
     * Detect variable-variable dynamic dispatch ($$var()) in executable PHP only.
     */
    private function detectVariableVariable(
        string $execOnly, string $file, bool $hasObfuscation, array &$findings
    ): void {
        if (!preg_match_all('/\$\$[a-zA-Z_]\w*\s*\(/', $execOnly, $matches, PREG_OFFSET_CAPTURE)) {
            return;
        }

        foreach ($matches[0] as $match) {
            $line = substr_count(substr($execOnly, 0, $match[1]), "\n") + 1;

            $findings[] = Finding::create([
                'ruleId'      => 'BACK-004',
                'title'       => 'Variable-Variable Dynamic Dispatch',
                'filePath'    => $file,
                'line'        => $line,
                'severity'    => $hasObfuscation ? Severity::HIGH : Severity::MEDIUM,
                'confidence'  => Confidence::MEDIUM,
                'category'    => DetectionCategory::BACKDOOR,
                'description' => 'Variable-variable ($$var) used to call a function dynamically.',
                'explanation' => 'Variable variables allow attackers to call arbitrary functions by controlling variable names. '
                               . 'This pattern is rarely used in legitimate WP code.',
                'remediation' => 'Replace with an explicit whitelist of callable function names.',
                'evidence'    => [$this->makeEvidence($line, $match[0], 'Variable-variable dispatch')],
                'tags'        => ['backdoor', 'dynamic-dispatch'],
            ]);
        }
    }
}
