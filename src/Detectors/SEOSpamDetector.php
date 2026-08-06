<?php

declare(strict_types=1);

namespace Wpma\Detectors;

use Wpma\Models\AnalysisObject;
use Wpma\Models\Confidence;
use Wpma\Models\DetectionCategory;
use Wpma\Models\Finding;
use Wpma\Models\Severity;

/**
 * SEOSpamDetector — detects SEO spam injection, doorway pages, and cloaking.
 * Covers the malware patterns seen in the news/index.php and news/amp/index.php samples.
 */
class SEOSpamDetector extends AbstractDetector
{
    public function getName(): string    { return 'SEOSpamDetector'; }
    public function getVersion(): string { return '1.1.0'; }

    // ── Trusted domains — never flagged as attacker infrastructure ────────────
    // These are well-known services used legitimately by WP plugins/themes.
    private const TRUSTED_DOMAINS = [
        // WordPress ecosystem
        'wordpress.org', 'wordpress.com', 'wp.com', 'wpengine.com',
        'woocommerce.com', 'gravatar.com', 'akismet.com', 'automattic.com',
        'wpbeaverbuilder.com', 'elementor.com', 'yoast.com', 'rankmath.com',
        'wordfence.com', 'sucuri.net', 'ithemes.com', 'wpforms.com',
        'gravityforms.com', 'advancedcustomfields.com', 'wpallimport.com',
        // Security / monitoring
        'wordfence.com', 'malcare.com', 'siteground.com', 'wpvulndb.com',
        // Auth / identity
        'google.com', 'googleapis.com', 'accounts.google.com',
        'facebook.com', 'twitter.com', 'linkedin.com', 'microsoft.com',
        'github.com', 'gitlab.com', 'bitbucket.org',
        // CDN / infrastructure
        'cloudflare.com', 'fastly.net', 'amazonaws.com', 'cloudfront.net',
        'googleusercontent.com', 'googleapis.com', 'gstatic.com',
        'jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com',
        // PHP / developer resources
        'php.net', 'composer.org', 'packagist.org', 'getcomposer.org',
        // Email marketing (plugins reference these legitimately)
        'mailchimp.com', 'list-manage.com', 'constantcontact.com',
        'icontact.com', 'aweber.com', 'getresponse.com', 'campaignmonitor.com',
        'activecampaign.com', 'drip.com', 'convertkit.com', 'klaviyo.com',
        'mailerlite.com', 'sendinblue.com', 'hubspot.com', 'sendgrid.com',
        // Payment
        'paypal.com', 'stripe.com', 'braintreepayments.com', 'authorize.net',
        // Shopify
        'shopify.com', 'myshopify.com', 'shopifycdn.com',
    ];
    public function getRuleId(): string  { return 'SEO'; }

    public function getSupportedExtensions(): array
    {
        return ['*']; // Scan all file types including pure HTML/PHP files without open tags
    }

    // ── keyword sets ──────────────────────────────────────────────────────────

    private const GAMBLING_KEYWORDS = [
        'togel', 'slot online', 'casino', 'poker online', 'judi', 'betting',
        'sportsbook', 'bandar', 'agen slot', 'gacor', 'rtp slot', 'jackpot',
        'pragmatic play', 'pg soft', 'live casino', 'toto', 'lotere',
        'spin', 'scatter', 'maxwin', 'deposit slot',
    ];

    private const PHARMA_KEYWORDS = [
        'viagra', 'cialis', 'levitra', 'sildenafil', 'tadalafil',
        'pharmacy', 'buy pills', 'cheap meds', 'prescription drugs',
        'weight loss pills', 'diet pills',
    ];

    private const ADULT_KEYWORDS = [
        'porn', 'xxx', 'sex videos', 'nude', 'escort', 'webcam girls',
        'adult dating', 'onlyfans',
    ];

    private const JAPANESE_SEO_PATTERNS = [
        '/[\x{3040}-\x{309F}]+/u',  // Hiragana
        '/[\x{30A0}-\x{30FF}]+/u',  // Katakana
        '/[\x{4E00}-\x{9FFF}]+/u',  // CJK Unified Ideographs
    ];

    // ── cloaking patterns ────────────────────────────────────────────────────
    // Only flag when user-agent check is combined with spam keywords or external redirects
    private const CLOAKING_PATTERNS = [
        '/strpos\s*\(\s*\$_(SERVER|ENV).*(?:Googlebot|bingbot|YandexBot|AhrefsBot|SemrushBot)/i',
        '/preg_match\s*\(.*(?:Googlebot|bingbot|YandexBot).*header\s*\(\s*[\'"]Location/is',
    ];

    // ── hidden link patterns ─────────────────────────────────────────────────

    private const HIDDEN_LINK_PATTERNS = [
        '/display\s*:\s*none/i',
        '/visibility\s*:\s*hidden/i',
        '/font-size\s*:\s*0/i',
        '/opacity\s*:\s*0/i',
        '/color\s*:\s*#(?:fff|ffffff|white)\b/i',
        '/position\s*:\s*absolute.*(?:top|left)\s*:\s*-\d{3,}/i',
    ];

    public function detect(AnalysisObject $ao): array
    {
        $findings = [];
        $content  = $ao->rawContent;
        $lower    = strtolower($content);
        $file     = $ao->meta->filePath;

        foreach ($this->detectSuspiciousMassContentInjection($ao) as $massInjectionFinding) {
            $findings[] = $massInjectionFinding;
        }

        // ── 1. Gambling spam ─────────────────────────────────────────────────
        $gamblingHits = [];
        foreach (self::GAMBLING_KEYWORDS as $kw) {
            if (str_contains($lower, $kw)) {
                $gamblingHits[] = $kw;
            }
        }
        if (count($gamblingHits) >= 3) {
            $line = $this->findKeywordLine($content, $gamblingHits[0]);
            $findings[] = Finding::create([
                'ruleId'      => 'SEO-001',
                'title'       => 'Gambling/Lottery SEO Spam Injection',
                'filePath'    => $file,
                'line'        => $line,
                'severity'    => Severity::HIGH,
                'confidence'  => Confidence::HIGH,
                'category'    => DetectionCategory::SEO_SPAM,
                'description' => 'File contains gambling/togel/casino spam keywords injected to manipulate search rankings.',
                'explanation' => 'Attackers inject gambling keywords into legitimate pages to hijack organic search traffic. ' .
                                 'Found keywords: ' . implode(', ', array_slice($gamblingHits, 0, 8)) . '.',
                'remediation' => 'Delete this file if it is not a legitimate page. Check your CMS for injected content and restore from a clean backup.',
                'evidence'    => [$this->makeEvidence($line, implode(', ', array_slice($gamblingHits, 0, 5)), 'Gambling keywords found')],
                'tags'        => ['seo-spam', 'gambling', 'togel'],
            ]);
        }

        // ── 2. Pharma spam ───────────────────────────────────────────────────
        $pharmaHits = [];
        foreach (self::PHARMA_KEYWORDS as $kw) {
            if (str_contains($lower, $kw)) {
                $pharmaHits[] = $kw;
            }
        }
        if (count($pharmaHits) >= 2) {
            $line = $this->findKeywordLine($content, $pharmaHits[0]);
            $findings[] = Finding::create([
                'ruleId'      => 'SEO-002',
                'title'       => 'Pharmaceutical SEO Spam Injection',
                'filePath'    => $file,
                'line'        => $line,
                'severity'    => Severity::HIGH,
                'confidence'  => Confidence::HIGH,
                'category'    => DetectionCategory::SEO_SPAM,
                'description' => 'File contains pharmaceutical spam keywords (viagra, cialis, etc.) injected for SEO manipulation.',
                'explanation' => 'Known "pharma hack" pattern — injects drug keywords into legitimate pages. Found: ' . implode(', ', $pharmaHits),
                'remediation' => 'Delete this file or remove injected content. Audit your site for similar pages.',
                'evidence'    => [$this->makeEvidence($line, implode(', ', $pharmaHits), 'Pharma keywords found')],
                'tags'        => ['seo-spam', 'pharma-hack'],
            ]);
        }

        // ── 3. Adult content spam ────────────────────────────────────────────
        $adultHits = [];
        foreach (self::ADULT_KEYWORDS as $kw) {
            if (str_contains($lower, $kw)) {
                $adultHits[] = $kw;
            }
        }
        if (count($adultHits) >= 2) {
            $line = $this->findKeywordLine($content, $adultHits[0]);
            $findings[] = Finding::create([
                'ruleId'      => 'SEO-003',
                'title'       => 'Adult Content SEO Spam Injection',
                'filePath'    => $file,
                'line'        => $line,
                'severity'    => Severity::HIGH,
                'confidence'  => Confidence::HIGH,
                'category'    => DetectionCategory::SEO_SPAM,
                'description' => 'File contains adult content spam keywords injected for SEO manipulation.',
                'explanation' => 'Adult spam injection redirects search engine traffic to malicious sites. Found: ' . implode(', ', $adultHits),
                'remediation' => 'Delete this file. Audit other PHP files for similar content.',
                'evidence'    => [$this->makeEvidence($line, implode(', ', $adultHits), 'Adult keywords found')],
                'tags'        => ['seo-spam', 'adult'],
            ]);
        }

        // ── 4. Cloaking ──────────────────────────────────────────────────────
        foreach (self::CLOAKING_PATTERNS as $pattern) {
            if (preg_match($pattern, $content, $match, PREG_OFFSET_CAPTURE)) {
                $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                $findings[] = Finding::create([
                    'ruleId'      => 'SEO-004',
                    'title'       => 'Search Engine Cloaking Detected',
                    'filePath'    => $file,
                    'line'        => $line,
                    'severity'    => Severity::CRITICAL,
                    'confidence'  => Confidence::HIGH,
                    'category'    => DetectionCategory::SEO_SPAM,
                    'description' => 'Code serves different content to search engine bots than to human visitors.',
                    'explanation' => 'Cloaking is a black-hat SEO technique that shows search engines spam content while showing humans the real page. This is a core indicator of a spam doorway page.',
                    'remediation' => 'Delete this file immediately. This is a doorway/cloaking page injected by attackers.',
                    'evidence'    => [$this->makeEvidence($line, $match[0][0], 'Cloaking pattern detected')],
                    'tags'        => ['seo-spam', 'cloaking'],
                ]);
                break;
            }
        }

        // ── 5. Hidden links ──────────────────────────────────────────────────
        // Only flag when: 2+ CSS hiding patterns AND at least one untrusted external link
        $hiddenLinkHits = 0;
        foreach (self::HIDDEN_LINK_PATTERNS as $pattern) {
            if (preg_match($pattern, $content)) {
                $hiddenLinkHits++;
            }
        }
        if ($hiddenLinkHits >= 2 && $this->hasSuspiciousExternalLinks($content, $ao)) {
            // Additional gate: don't flag if this looks like a legitimate WP theme/plugin
            // (they use display:none legitimately for dropdowns, modals, etc.)
            // Only flag when there are also spam keywords OR an untrusted redirect
            $hasSpamContext = \count($gamblingHits) >= 1
                || \count($pharmaHits) >= 1
                || \count($adultHits) >= 1;

            if ($hasSpamContext) {
                $findings[] = Finding::create([
                    'ruleId'      => 'SEO-005',
                    'title'       => 'Hidden Link Injection Detected',
                    'filePath'    => $file,
                    'line'        => 1,
                    'severity'    => Severity::HIGH,
                    'confidence'  => Confidence::MEDIUM,
                    'category'    => DetectionCategory::SEO_SPAM,
                    'description' => 'CSS techniques hide links from visitors while keeping them visible to search engines.',
                    'explanation' => 'Hidden link injection builds backlinks to spam sites without users noticing. '
                                   . 'This finding requires: 2+ CSS hiding techniques + untrusted external links + spam keyword context.',
                    'remediation' => 'Remove all hidden link blocks. Audit template files and active plugins.',
                    'evidence'    => [$this->makeEvidence(1, 'display:none / visibility:hidden + spam context + untrusted external links', 'Hidden link injection')],
                    'tags'        => ['seo-spam', 'hidden-links'],
                ]);
            }
        }

        // ── 6. Doorway page (pure spam content, no legitimate WP code) ───────
        if ($this->isDoorwayPage($content, $ao)) {
            $findings[] = Finding::create([
                'ruleId'      => 'SEO-006',
                'title'       => 'Spam Doorway Page Detected',
                'filePath'    => $file,
                'line'        => 1,
                'severity'    => Severity::CRITICAL,
                'confidence'  => Confidence::HIGH,
                'category'    => DetectionCategory::SEO_SPAM,
                'description' => 'File appears to be a spam doorway page — a fake page designed only to rank in search engines for spam keywords.',
                'explanation' => 'Doorway pages are entire fake pages injected by attackers. They rank for spam search terms and redirect visitors to malicious sites. This file contains all hallmarks: spam brand name, external redirect links, no legitimate WP content.',
                'remediation' => 'Delete this file immediately. Scan the rest of your site for similar files. Change all admin passwords and WordPress secret keys.',
                'evidence'    => [$this->makeEvidence(1, 'File is a spam doorway page with gambling/spam content', 'Doorway page indicators')],
                'tags'        => ['seo-spam', 'doorway-page'],
            ]);
        }

        // ── 7. External attacker redirect links (login/register to foreign domain) ──
        if (preg_match_all(
            '#href=[\'"]https?://([^/"\']+)/[^"\']*(?:login|register|daftar|masuk|signup)[^"\']*[\'"]#i',
            $content, $matches, PREG_OFFSET_CAPTURE
        )) {
            $ownDomain = '';
            if (preg_match('#<link[^>]+rel=["\']canonical["\'][^>]+href=["\']https?://([^/"]+)#i', $content, $cm)) {
                $ownDomain = strtolower($cm[1]);
            }

            foreach ($matches[0] as $idx => $match) {
                $linkDomain = strtolower($matches[1][$idx][0]);
                // Skip if link domain is the site's own domain or a known safe service
                if ($ownDomain !== '' && $linkDomain === $ownDomain) continue;
                if ($this->isSafeRedirectDomain($linkDomain)) continue;

                $line = substr_count(substr($content, 0, $match[1]), "\n") + 1;
                $findings[] = Finding::create([
                    'ruleId'      => 'SEO-007',
                    'title'       => 'External Login/Register Redirect to Attacker Domain',
                    'filePath'    => $file,
                    'line'        => $line,
                    'severity'    => Severity::CRITICAL,
                    'confidence'  => Confidence::HIGH,
                    'category'    => DetectionCategory::SEO_SPAM,
                    'description' => "Login or registration link redirects to external domain: {$linkDomain}",
                    'explanation' => 'Spam doorway pages redirect visitors to attacker-controlled gambling or phishing sites via login/register buttons. This is a core indicator of a hijacked page.',
                    'remediation' => 'Delete this file immediately. It is a spam page injected by attackers to redirect your visitors.',
                    'evidence'    => [$this->makeEvidence($line, $match[0], 'External redirect link')],
                    'tags'        => ['seo-spam', 'redirect', 'doorway-page'],
                ]);
                break; // Report first occurrence only
            }
        }

        return $findings;
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /**
     * @return Finding[]
     */
    private function detectSuspiciousMassContentInjection(AnalysisObject $ao): array
    {
        $findings = [];
        $currentFile = (string) ($ao->meta->filePath ?? '');

        foreach ($ao->functionCalls as $postMutationCall) {
            $lower = strtolower($postMutationCall->name);
            if ($lower !== 'wp_insert_post' && $lower !== 'wp_update_post') {
                continue;
            }

            $context = $this->buildOperationContext($ao, $postMutationCall);
            $parsedArray = $this->parsePhpArrayArgs($postMutationCall->args);
            $postTitleValue = $parsedArray['post_title'] ?? null;
            $postContentValue = $parsedArray['post_content'] ?? null;
            $postStatusValue = $parsedArray['post_status'] ?? null;
            $postTypeValue = $parsedArray['post_type'] ?? null;

            if (!$this->mutationHasRelevantContentFields($postTitleValue, $postContentValue)) {
                continue;
            }

            $relevantExpressions = array_values(array_filter([
                $postTitleValue,
                $postContentValue,
            ], static fn (?string $value): bool => $value !== null && trim($value) !== ''));

            if ($relevantExpressions === []) {
                continue;
            }

            $relevantAssignments = $this->resolveRelevantAssignmentsBeforeLine($ao, $relevantExpressions, $postMutationCall->line);
            $relevantText = implode("\n", $relevantExpressions);
            $assignmentText = implode("\n", array_map(static fn ($assignment): string => $assignment->expression, $relevantAssignments));
            $combinedRelevantText = trim($relevantText . "\n" . $assignmentText);

            $hasDangerousInput = $this->expressionUsesUserInput($relevantText)
                || $this->assignmentsUseUserInput($relevantAssignments);
            $hasRemoteContent = $this->expressionHasRemoteContent($relevantText)
                || $this->assignmentsContainRemoteContent($relevantAssignments);
            $hasEncodedPayload = $this->expressionHasEncodedPayload($relevantText)
                || $this->assignmentsContainDecodeFunction($relevantAssignments);
            $hasSpamKeywordContext = $this->analyzeSpamKeywordContext($combinedRelevantText)['detected'];
            $hasHiddenLinkContext = $this->analyzeHiddenLinkContext($combinedRelevantText)['detected'];
            $payloadIocs = $this->extractRelevantContentIocs($ao, $currentFile, $combinedRelevantText, $relevantAssignments, $context);
            $hasMassCreationSignal = $this->operationHasMassCreationSignal($context, $postMutationCall);
            $hasElevatedObfuscation = ($hasEncodedPayload || $hasHiddenLinkContext)
                && $context !== null
                && $this->contextHasElevatedObfuscation($context);

            $hasStrongCorroboration = ($hasDangerousInput && ($hasSpamKeywordContext || $hasHiddenLinkContext || $hasRemoteContent || $hasMassCreationSignal))
                || ($hasRemoteContent && ($hasSpamKeywordContext || $hasHiddenLinkContext || $hasEncodedPayload || $hasMassCreationSignal))
                || ($hasEncodedPayload && ($hasSpamKeywordContext || $hasHiddenLinkContext || $hasDangerousInput || $hasMassCreationSignal))
                || ($hasMassCreationSignal && ($hasSpamKeywordContext || $hasDangerousInput || $hasRemoteContent || $hasEncodedPayload))
                || (!empty($payloadIocs) && ($hasSpamKeywordContext || $hasHiddenLinkContext || $hasRemoteContent));

            if (!$hasStrongCorroboration) {
                continue;
            }

            $signals = ['programmatically creates or updates WordPress content'];
            if ($postTitleValue !== null) {
                $signals[] = 'mutates post_title';
            }
            if ($postContentValue !== null) {
                $signals[] = 'mutates post_content';
            }
            if ($postStatusValue !== null) {
                $signals[] = 'sets post_status to ' . trim($postStatusValue, "'\"");
            }
            if ($postTypeValue !== null) {
                $signals[] = 'targets post_type ' . trim($postTypeValue, "'\"");
            }
            if ($hasMassCreationSignal) {
                $signals[] = 'specific mutation is governed by loop or bulk-creation flow';
            }
            if ($hasSpamKeywordContext) {
                $signals[] = 'title/content contains SEO spam keyword context';
            }
            if ($hasHiddenLinkContext) {
                $signals[] = 'title/content contains hidden SEO link indicators';
            }
            if ($hasRemoteContent) {
                $signals[] = 'title/content uses remote or downloaded content';
            }
            if ($hasEncodedPayload) {
                $signals[] = 'title/content uses encoded or decoded payload material';
            }
            if ($hasDangerousInput) {
                $signals[] = 'title/content uses attacker-controlled input';
            }
            if ($hasElevatedObfuscation) {
                $signals[] = sprintf('governing flow has elevated obfuscation score (%.2f)', $ao->features->obfuscationScore);
            }
            if (!empty($payloadIocs)) {
                $signals[] = 'title/content carries suspicious remote content IOCs';
            }

            $findings[] = Finding::create([
                'ruleId'      => 'SEO-008',
                'title'       => 'Suspicious WordPress mass content injection',
                'filePath'    => $currentFile,
                'line'        => $postMutationCall->line,
                'severity'    => ($hasDangerousInput && ($hasSpamKeywordContext || $hasHiddenLinkContext || $hasRemoteContent || $hasEncodedPayload)) ? Severity::CRITICAL : Severity::HIGH,
                'confidence'  => count($signals) >= 4 ? Confidence::HIGH : Confidence::MEDIUM,
                'category'    => DetectionCategory::SEO_SPAM,
                'description' => 'This file programmatically inserts or updates WordPress post title or content with correlated SEO-spam or mass-injection signals.',
                'explanation' => 'wp_insert_post() and wp_update_post() are legitimate APIs and are not flagged on their own. This finding is emitted only when a specific content/title mutation is correlated with stronger title/content-local or operation-local indicators such as attacker-controlled content, hidden SEO links, spam keywords, remote downloaded content, encoded payload material, or bulk automation behavior. Correlated signals: ' . implode('; ', $signals) . '.',
                'remediation' => 'Review this content-creation code path. If it inserts spam pages, hidden links, or remote payload text outside an expected authenticated publishing/import workflow, remove it and audit recently created WordPress posts and pages.',
                'evidence'    => [
                    $this->makeEvidence(
                        $postMutationCall->line,
                        $this->snippet($ao->rawContent, $postMutationCall->line),
                        'WordPress content mutation API: ' . $postMutationCall->name . '()'
                    ),
                ],
                'iocs'        => $payloadIocs,
                'tags'        => ['seo-spam', 'content-injection', 'mass-post-creation', 'wordpress-posts'],
            ]);
        }

        return $findings;
    }

    private function findKeywordLine(string $content, string $keyword): int
    {
        $lines = explode("\n", $content);
        foreach ($lines as $i => $line) {
            if (stripos($line, $keyword) !== false) {
                return $i + 1;
            }
        }
        return 1;
    }

    private function hasSuspiciousExternalLinks(string $content, AnalysisObject $ao): bool
    {
        // Only flag if there's at least one IOC that is an untrusted external domain
        foreach ($ao->iocs as $ioc) {
            if ($ioc->type === \Wpma\Models\IOCType::URL && !$ioc->isKnownWpService) {
                $host = parse_url($ioc->value, PHP_URL_HOST) ?: '';
                if ($host !== '' && !$this->isTrustedDomain(strtolower($host))) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Unified domain trust check used by all SEO detection rules.
     * Returns true for any domain that is known legitimate infrastructure.
     */
    private function isTrustedDomain(string $domain): bool
    {
        foreach (self::TRUSTED_DOMAINS as $trusted) {
            if ($domain === $trusted || str_ends_with($domain, '.' . $trusted)) {
                return true;
            }
        }
        return false;
    }

    private function isSafeRedirectDomain(string $domain): bool
    {
        return $this->isTrustedDomain($domain);
    }

    private function isDoorwayPage(string $content, AnalysisObject $ao): bool
    {
        $lower = strtolower($content);

        // Must have multiple gambling hits AND external login/register links AND no real WP structure
        $gamblingCount = 0;
        foreach (self::GAMBLING_KEYWORDS as $kw) {
            if (str_contains($lower, $kw)) {
                $gamblingCount++;
            }
        }

        $hasExternalLoginLink = preg_match('#href=[\'"]https?://[^/]+/[^"\']*(?:login|register|daftar|masuk)[^"\']*[\'"]#i', $content);
        $hasLegitWpCode       = str_contains($lower, 'wp-content') || str_contains($lower, 'wp_') || str_contains($lower, 'get_template');

        return $gamblingCount >= 5 && $hasExternalLoginLink && !$hasLegitWpCode;
    }

    private function resolveFirstAssignedVariable(AnalysisObject $ao, string $expression): ?\Wpma\Models\VariableAssignment
    {
        if (preg_match('/\$[a-zA-Z_][\w]*/', $expression, $m) !== 1) {
            return null;
        }

        return $ao->findAssignmentForVariable($m[0]);
    }

    private function buildOperationContext(AnalysisObject $ao, \Wpma\Models\FunctionCall $triggerCall): ?array
    {
        $functionRanges = $this->buildSameFileFunctionBodyRanges($ao->tokens);
        foreach ($functionRanges as $range) {
            if ($triggerCall->line < $range['startLine'] || $triggerCall->line > $range['endLine']) {
                continue;
            }

            $bodyTokens = array_slice($ao->tokens, $range['startIndex'], $range['endIndex'] - $range['startIndex'] + 1);
            $bodyText = $this->tokensToString($bodyTokens, 0, count($bodyTokens) - 1);
            $range['bodyText'] = $bodyText;

            return $range;
        }

        return null;
    }

    private function mutationHasRelevantContentFields(?string $postTitleValue, ?string $postContentValue): bool
    {
        return ($postTitleValue !== null && trim($postTitleValue) !== '')
            || ($postContentValue !== null && trim($postContentValue) !== '');
    }

    /**
     * @param string[] $expressions
     * @return \Wpma\Models\VariableAssignment[]
     */
    private function resolveRelevantAssignmentsBeforeLine(AnalysisObject $ao, array $expressions, int $line): array
    {
        $assignments = [];
        $seen = [];

        foreach ($expressions as $expression) {
            if (preg_match_all('/\$[a-zA-Z_][\w]*/', $expression, $matches) !== 1) {
                continue;
            }

            foreach (array_unique($matches[0]) as $variableName) {
                $assignment = $ao->findAssignmentForVariableBeforeLine($variableName, $line);
                if ($assignment === null) {
                    continue;
                }

                $key = $assignment->variableName . ':' . $assignment->line;
                if (isset($seen[$key])) {
                    continue;
                }

                $seen[$key] = true;
                $assignments[] = $assignment;
            }
        }

        return $assignments;
    }

    private function expressionUsesUserInput(string $expression): bool
    {
        return preg_match('/\$_(POST|GET|REQUEST|COOKIE|SERVER|FILES)\b/', $expression) === 1;
    }

    /**
     * @param \Wpma\Models\VariableAssignment[] $assignments
     */
    private function assignmentsUseUserInput(array $assignments): bool
    {
        foreach ($assignments as $assignment) {
            if ($assignment->usesUserInput) {
                return true;
            }
        }

        return false;
    }

    private function expressionHasRemoteContent(string $expression): bool
    {
        return preg_match('/https?:\/\/|wp_remote_get\s*\(|wp_remote_post\s*\(|file_get_contents\s*\(|curl_exec\s*\(/i', $expression) === 1;
    }

    /**
     * @param \Wpma\Models\VariableAssignment[] $assignments
     */
    private function assignmentsContainRemoteContent(array $assignments): bool
    {
        foreach ($assignments as $assignment) {
            if ($this->assignmentContainsRemoteContent($assignment)) {
                return true;
            }
        }

        return false;
    }

    private function assignmentContainsRemoteContent(\Wpma\Models\VariableAssignment $assignment): bool
    {
        if (preg_match('/https?:\/\//i', $assignment->expression) === 1) {
            return true;
        }

        foreach ($assignment->functionNames as $functionName) {
            if (in_array(strtolower($functionName), ['wp_remote_get', 'wp_remote_post', 'file_get_contents', 'curl_exec'], true)) {
                return true;
            }
        }

        return false;
    }

    private function expressionHasEncodedPayload(string $expression): bool
    {
        if (preg_match('/[A-Za-z0-9+\/]{20,}={0,2}/', $expression) === 1) {
            return true;
        }

        return preg_match('/\b(base64_decode|gzinflate|gzdecode|gzuncompress|str_rot13|hex2bin|rawurldecode)\s*\(/i', $expression) === 1;
    }

    /**
     * @param \Wpma\Models\VariableAssignment[] $assignments
     */
    private function assignmentsContainDecodeFunction(array $assignments): bool
    {
        foreach ($assignments as $assignment) {
            if ($this->assignmentContainsDecodeFunction($assignment)) {
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

    private function operationHasMassCreationSignal(?array $context, \Wpma\Models\FunctionCall $triggerCall): bool
    {
        if ($context === null) {
            return false;
        }

        if ($this->isLineInsideLoopTokens($context['tokens'] ?? [], $triggerCall->line)) {
            return true;
        }

        return preg_match('/\barray_map\s*\(/i', $this->extractLineWindow($context['bodyText'], $triggerCall->line, $context['startLine'], 6)) === 1;
    }

    private function contextHasElevatedObfuscation(array $context): bool
    {
        $bodyText = (string) ($context['bodyText'] ?? '');
        $stringNames = [];
        foreach (($context['tokens'] ?? []) as $token) {
            if ($token->id === \T_STRING) {
                $stringNames[] = strtolower($token->text);
            }
        }

        $score = 0.0;
        if ($this->expressionHasEncodedPayload($bodyText)) {
            $score += 0.3;
        }
        if (preg_match('/\b(eval|assert)\s*\(/i', $bodyText) === 1) {
            $score += 0.3;
        }
        if (preg_match('/\$\$|\$[a-zA-Z_][\w]*\s*\(/', $bodyText) === 1) {
            $score += 0.2;
        }
        if (preg_match('/(?:chr\s*\(|fromCharCode|pack\s*\(|unpack\s*\()/i', $bodyText) === 1) {
            $score += 0.2;
        }
        if (array_intersect($stringNames, ['base64_decode', 'gzinflate', 'gzdecode', 'gzuncompress', 'str_rot13', 'hex2bin', 'rawurldecode']) !== []) {
            $score += 0.2;
        }

        return $score > 0.35;
    }

    private function containsSpamKeywordContext(string $content): bool
    {
        return $this->analyzeSpamKeywordContext($content)['detected'];
    }

    private function containsHiddenLinkContext(string $content): bool
    {
        return $this->analyzeHiddenLinkContext($content)['detected'];
    }

    /**
     * @param \Wpma\Models\VariableAssignment[] $relevantAssignments
     * @return array
     */
    private function extractRelevantContentIocs(AnalysisObject $ao, string $currentFile, string $combinedRelevantText, array $relevantAssignments, ?array $context): array
    {
        $matches = [];
        $allowedLines = [];

        if ($context !== null) {
            foreach (($context['tokens'] ?? []) as $token) {
                if ($token->line > 0) {
                    $allowedLines[$token->line] = true;
                }
            }
        }

        foreach ($relevantAssignments as $assignment) {
            $allowedLines[$assignment->line] = true;
        }

        foreach ($ao->iocs as $ioc) {
            if ($ioc->filePath !== $currentFile) {
                continue;
            }

            if (($ioc->type !== \Wpma\Models\IOCType::URL && $ioc->type !== \Wpma\Models\IOCType::DOMAIN)
                || $ioc->isKnownWpService
            ) {
                continue;
            }

            if (!isset($allowedLines[$ioc->line])) {
                continue;
            }

            if (!str_contains($combinedRelevantText, $ioc->value)) {
                continue;
            }

            $matches[] = $ioc;
        }

        return $matches;
    }

    private function parsePhpArrayArgs(array $args): array
    {
        $result = [];
        $arrayExpression = trim($args[0] ?? '');

        if ($arrayExpression === '' || ($arrayExpression[0] ?? '') !== '[') {
            return $result;
        }

        $length = strlen($arrayExpression);
        $current = '';
        $parenDepth = 0;
        $bracketDepth = 0;
        $braceDepth = 0;
        $quote = null;
        $entries = [];

        for ($i = 1; $i < $length - 1; $i++) {
            $ch = $arrayExpression[$i];
            $prev = $i > 0 ? $arrayExpression[$i - 1] : '';

            if ($quote !== null) {
                $current .= $ch;
                if ($ch === $quote && $prev !== '\\') {
                    $quote = null;
                }
                continue;
            }

            if ($ch === '\'' || $ch === '"') {
                $quote = $ch;
                $current .= $ch;
                continue;
            }

            if ($ch === '(') {
                $parenDepth++;
                $current .= $ch;
                continue;
            }
            if ($ch === ')') {
                $parenDepth = max(0, $parenDepth - 1);
                $current .= $ch;
                continue;
            }
            if ($ch === '[') {
                $bracketDepth++;
                $current .= $ch;
                continue;
            }
            if ($ch === ']') {
                $bracketDepth = max(0, $bracketDepth - 1);
                $current .= $ch;
                continue;
            }
            if ($ch === '{') {
                $braceDepth++;
                $current .= $ch;
                continue;
            }
            if ($ch === '}') {
                $braceDepth = max(0, $braceDepth - 1);
                $current .= $ch;
                continue;
            }

            if ($ch === ',' && $parenDepth === 0 && $bracketDepth === 0 && $braceDepth === 0) {
                $trimmed = trim($current);
                if ($trimmed !== '') {
                    $entries[] = $trimmed;
                }
                $current = '';
                continue;
            }

            $current .= $ch;
        }

        $trimmed = trim($current);
        if ($trimmed !== '') {
            $entries[] = $trimmed;
        }

        foreach ($entries as $entry) {
            $separatorPos = $this->findTopLevelArraySeparator($entry);
            if ($separatorPos === null) {
                continue;
            }

            $key = trim(substr($entry, 0, $separatorPos));
            $value = trim(substr($entry, $separatorPos + 2));
            $key = trim($key, "'\"");
            if ($key === '') {
                continue;
            }

            $result[$key] = $value;
        }

        return $result;
    }

    private function findTopLevelArraySeparator(string $entry): ?int
    {
        $length = strlen($entry);
        $parenDepth = 0;
        $bracketDepth = 0;
        $braceDepth = 0;
        $quote = null;

        for ($i = 0; $i < $length - 1; $i++) {
            $ch = $entry[$i];
            $prev = $i > 0 ? $entry[$i - 1] : '';

            if ($quote !== null) {
                if ($ch === $quote && $prev !== '\\') {
                    $quote = null;
                }
                continue;
            }

            if ($ch === '\'' || $ch === '"') {
                $quote = $ch;
                continue;
            }

            if ($ch === '(') {
                $parenDepth++;
                continue;
            }
            if ($ch === ')') {
                $parenDepth = max(0, $parenDepth - 1);
                continue;
            }
            if ($ch === '[') {
                $bracketDepth++;
                continue;
            }
            if ($ch === ']') {
                $bracketDepth = max(0, $bracketDepth - 1);
                continue;
            }
            if ($ch === '{') {
                $braceDepth++;
                continue;
            }
            if ($ch === '}') {
                $braceDepth = max(0, $braceDepth - 1);
                continue;
            }

            if ($ch === '=' && ($entry[$i + 1] ?? '') === '>' && $parenDepth === 0 && $bracketDepth === 0 && $braceDepth === 0) {
                return $i;
            }
        }

        return null;
    }

    private function analyzeSpamKeywordContext(string $content): array
    {
        $lower = strtolower($content);
        $hits = [];

        foreach (array_merge(self::GAMBLING_KEYWORDS, self::PHARMA_KEYWORDS, self::ADULT_KEYWORDS) as $keyword) {
            if (str_contains($lower, $keyword)) {
                $hits[] = $keyword;
            }
        }

        return ['detected' => count($hits) >= 1, 'hits' => $hits];
    }

    private function analyzeHiddenLinkContext(string $content): array
    {
        $matchedPatterns = [];
        foreach (self::HIDDEN_LINK_PATTERNS as $pattern) {
            if (preg_match($pattern, $content) === 1) {
                $matchedPatterns[] = $pattern;
            }
        }

        $hasAnchor = preg_match('/<a\s+[^>]*href=/i', $content) === 1;

        return [
            'detected' => count($matchedPatterns) >= 2 && $hasAnchor,
            'matchedPatterns' => $matchedPatterns,
            'hasAnchor' => $hasAnchor,
        ];
    }

    /**
     * @param array $tokens
     * @return array<int, array{startLine:int,endLine:int,startIndex:int,endIndex:int,tokens:array}>
     */
    private function buildSameFileFunctionBodyRanges(array $tokens): array
    {
        $ranges = [];
        $count = count($tokens);

        for ($i = 0; $i < $count; $i++) {
            $token = $tokens[$i];
            if (!in_array($token->id, [\T_FUNCTION, \T_FN], true)) {
                continue;
            }

            $braceIndex = null;
            for ($j = $i + 1; $j < $count; $j++) {
                if ($tokens[$j]->text === '{') {
                    $braceIndex = $j;
                    break;
                }
                if ($tokens[$j]->text === ';') {
                    break;
                }
            }

            if ($braceIndex === null) {
                continue;
            }

            $depth = 0;
            for ($j = $braceIndex; $j < $count; $j++) {
                if ($tokens[$j]->text === '{') {
                    $depth++;
                } elseif ($tokens[$j]->text === '}') {
                    $depth--;
                    if ($depth === 0) {
                        $ranges[] = [
                            'startLine' => $tokens[$braceIndex]->line,
                            'endLine' => $tokens[$j]->line,
                            'startIndex' => $braceIndex,
                            'endIndex' => $j,
                            'tokens' => array_slice($tokens, $braceIndex, $j - $braceIndex + 1),
                        ];
                        break;
                    }
                }
            }
        }

        return $ranges;
    }

    /**
     * @param array $tokens
     */
    private function tokensToString(array $tokens, int $startIndex, int $endIndex): string
    {
        $buffer = '';
        for ($i = $startIndex; $i <= $endIndex; $i++) {
            if (!isset($tokens[$i])) {
                continue;
            }
            $buffer .= $tokens[$i]->text;
        }

        return $buffer;
    }

    /**
     * @param array $tokens
     */
    private function isLineInsideLoopTokens(array $tokens, int $line): bool
    {
        $count = count($tokens);
        for ($i = 0; $i < $count; $i++) {
            $token = $tokens[$i];
            if (!in_array($token->id, [\T_FOR, \T_FOREACH, \T_WHILE], true)) {
                continue;
            }

            $loopRange = $this->findLoopBodyLineRange($tokens, $i);
            if ($loopRange === null) {
                continue;
            }

            if ($line >= $loopRange['startLine'] && $line <= $loopRange['endLine']) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array $tokens
     * @return array{startLine:int,endLine:int}|null
     */
    private function findLoopBodyLineRange(array $tokens, int $loopIndex): ?array
    {
        $count = count($tokens);
        $parenDepth = 0;
        $seenOpeningParen = false;
        $bodyStartIndex = null;

        for ($i = $loopIndex + 1; $i < $count; $i++) {
            $text = $tokens[$i]->text;
            if ($text === '(') {
                $parenDepth++;
                $seenOpeningParen = true;
                continue;
            }
            if ($text === ')') {
                $parenDepth = max(0, $parenDepth - 1);
                if ($seenOpeningParen && $parenDepth === 0) {
                    for ($j = $i + 1; $j < $count; $j++) {
                        if ($tokens[$j]->id === \T_WHITESPACE || $tokens[$j]->id === \T_COMMENT || $tokens[$j]->id === \T_DOC_COMMENT) {
                            continue;
                        }
                        $bodyStartIndex = $j;
                        break 2;
                    }
                }
            }
        }

        if ($bodyStartIndex === null) {
            return null;
        }

        if ($tokens[$bodyStartIndex]->text === '{') {
            $depth = 0;
            for ($i = $bodyStartIndex; $i < $count; $i++) {
                if ($tokens[$i]->text === '{') {
                    $depth++;
                } elseif ($tokens[$i]->text === '}') {
                    $depth--;
                    if ($depth === 0) {
                        return [
                            'startLine' => $tokens[$bodyStartIndex]->line,
                            'endLine' => $tokens[$i]->line,
                        ];
                    }
                }
            }

            return null;
        }

        for ($i = $bodyStartIndex; $i < $count; $i++) {
            if ($tokens[$i]->text === ';') {
                return [
                    'startLine' => $tokens[$bodyStartIndex]->line,
                    'endLine' => $tokens[$i]->line,
                ];
            }
        }

        return null;
    }

    private function extractLineWindow(string $bodyText, int $targetLine, int $contextStartLine, int $radius): string
    {
        $lines = explode("\n", $bodyText);
        $relativeIndex = max(0, $targetLine - $contextStartLine);
        $start = max(0, $relativeIndex - $radius);
        $end = min(count($lines) - 1, $relativeIndex + $radius);

        return implode("\n", array_slice($lines, $start, $end - $start + 1));
    }
}
