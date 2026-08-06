<?php

declare(strict_types=1);

namespace Wpma\Detectors;

use Wpma\Models\AnalysisObject;
use Wpma\Models\Confidence;
use Wpma\Models\DetectionCategory;
use Wpma\Models\Finding;
use Wpma\Models\Severity;

/**
 * HtaccessDetector — detects malicious Apache directives in .htaccess files.
 *
 * Works entirely on $ao->rawContent using regex — no PHP tokenizer runs on
 * .htaccess files, so functionCalls and features are always empty here.
 *
 * Rules:
 *   HTAC-001  PHP execution handler assigned to non-PHP file types
 *             (allows images/CSS to execute as PHP — the image webshell technique)
 *   HTAC-002  PHP auto_prepend_file / auto_append_file
 *             (silently includes a PHP backdoor on every request)
 *   HTAC-003  Bot-targeting cloaking redirect
 *             (different content shown to search bots vs real visitors — SEO spam)
 *   HTAC-004  All-traffic unconditional redirect to external domain
 *             (blanket hijacking of the site's visitors)
 *   HTAC-005  ExecCGI enabled
 *             (allows arbitrary CGI/executable files to run as scripts)
 *   HTAC-006  PHP engine re-enabled in uploads or other non-PHP directories
 *             (bypasses the WordPress .htaccess that blocks PHP execution in uploads)
 */
class HtaccessDetector extends AbstractDetector
{
    public function getName(): string    { return 'HtaccessDetector'; }
    public function getVersion(): string { return '1.0.0'; }
    public function getRuleId(): string  { return 'HTAC'; }

    public function getSupportedExtensions(): array
    {
        return ['']; // .htaccess files have no extension
    }

    /**
     * Override: match on filename, not extension.
     * The parent implementation would check extension (always '') and would
     * match every extensionless file.
     */
    public function isApplicable(AnalysisObject $ao): bool
    {
        return basename($ao->meta->filePath) === '.htaccess';
    }

    public function detect(AnalysisObject $ao): array
    {
        $findings = [];
        $content  = $ao->rawContent;
        $file     = $ao->meta->filePath;

        // ── HTAC-001: PHP execution handler for arbitrary file types ──────────
        // SetHandler/AddType/AddHandler + application/x-httpd-php makes any file
        // type (images, CSS, etc.) executable as PHP. Never legitimate in WP.
        if (preg_match(
            '/(SetHandler|AddType|AddHandler)\s+application\/x-httpd-php/i',
            $content, $m, PREG_OFFSET_CAPTURE,
        )) {
            $line = $this->offsetToLine($content, $m[0][1]);
            $findings[] = Finding::create([
                'ruleId'      => 'HTAC-001',
                'title'       => 'PHP execution enabled for arbitrary file types',
                'filePath'    => $file,
                'line'        => $line,
                'severity'    => Severity::CRITICAL,
                'confidence'  => Confidence::HIGH,
                'category'    => DetectionCategory::BACKDOOR,
                'description' => sprintf(
                    'The directive "%s" assigns the PHP execution handler to file types '
                    . 'that are not normally executable. This enables image webshells — '
                    . 'an attacker can upload a .jpg file containing PHP code and execute it.',
                    trim($m[0][0]),
                ),
                'explanation' => 'Assigning application/x-httpd-php to non-PHP extensions '
                    . '(e.g. .jpg, .png, .gif, .css) means the web server will execute ANY '
                    . 'file of that type as PHP code, regardless of content. Attackers use '
                    . 'this to bypass file upload restrictions: a file named photo.jpg '
                    . 'containing <?php ... will execute as a webshell. This directive should '
                    . 'NEVER appear in a WordPress .htaccess or plugin/theme directory.',
                'remediation' => 'Remove this directive immediately. Check for recently uploaded '
                    . 'files with image/CSS extensions that contain PHP code. '
                    . 'Audit all .htaccess files on the server.',
                'evidence'    => [
                    $this->makeEvidence($line, $this->lineSnippet($content, $line), trim($m[0][0])),
                ],
                'tags'        => ['htaccess', 'php-handler', 'image-webshell', 'backdoor'],
            ]);
        }

        // ── HTAC-002: PHP auto_prepend_file / auto_append_file ────────────────
        // Silently includes a PHP file on EVERY request. Used to install a
        // persistent backdoor that runs before/after all legitimate PHP code.
        if (preg_match(
            '/php_value\s+auto_(prepend|append)_file\s+\S+/i',
            $content, $m, PREG_OFFSET_CAPTURE,
        )) {
            $line = $this->offsetToLine($content, $m[0][1]);
            $type = strtolower($m[1][0]) === 'prepend' ? 'auto_prepend_file' : 'auto_append_file';
            $findings[] = Finding::create([
                'ruleId'      => 'HTAC-002',
                'title'       => "PHP {$type} set in .htaccess",
                'filePath'    => $file,
                'line'        => $line,
                'severity'    => Severity::CRITICAL,
                'confidence'  => Confidence::HIGH,
                'category'    => DetectionCategory::PERSISTENCE,
                'description' => sprintf(
                    '"%s" is set in .htaccess. This causes PHP to silently include the '
                    . 'specified file on every single request, even for requests that do not '
                    . 'target the backdoor file directly.',
                    trim($m[0][0]),
                ),
                'explanation' => 'php_value auto_prepend_file and auto_append_file are '
                    . 'per-directory PHP configuration overrides that inject a PHP file '
                    . 'into every request processed under this directory. Attackers use '
                    . 'this to install a persistent backdoor that survives even if the '
                    . 'original infection vector is cleaned: as long as the injected '
                    . 'file and this .htaccess directive remain, the backdoor runs. '
                    . 'This directive almost never appears in legitimate WordPress code.',
                'remediation' => 'Remove this directive. Find and delete the file it references. '
                    . 'Search for similar directives in all .htaccess files on the server.',
                'evidence'    => [
                    $this->makeEvidence($line, $this->lineSnippet($content, $line), trim($m[0][0])),
                ],
                'tags'        => ['htaccess', 'auto-prepend', 'persistence', 'backdoor'],
            ]);
        }

        // ── HTAC-003: Bot-targeting cloaking redirect ─────────────────────────
        // RewriteCond matches a search bot User-Agent → RewriteRule redirects to
        // an external spam/malware domain. Real users see the normal site;
        // search bots see the attacker's content. Classic SEO spam cloaking.
        $botCondition = preg_match(
            '/RewriteCond\s+%\{HTTP_USER_AGENT\}.*\b(Google|Bing|Yahoo|MSN|bot|spider|crawl|slurp|baidu|yandex)\b/i',
            $content, $botMatch, PREG_OFFSET_CAPTURE,
        );
        $externalRedirect = preg_match(
            // Matches RewriteRule pointing to a static external http/https URL.
            // Negative lookaheads exclude common legitimate patterns:
            //   %{HTTP_HOST}  — www/non-www canonical redirect
            //   %{SERVER_NAME} — server-name based redirect
            //   %{HTTPS}      — not typically in a RewriteRule target
            '/RewriteRule\s+\S+\s+https?:\/\/(?!%\{HTTP_HOST\})(?!%\{SERVER_NAME\})/i',
            $content, $redirMatch, PREG_OFFSET_CAPTURE,
        );

        if ($botCondition && $externalRedirect) {
            $line = $this->offsetToLine($content, $botMatch[0][1]);
            $findings[] = Finding::create([
                'ruleId'      => 'HTAC-003',
                'title'       => 'Bot-targeting cloaking redirect in .htaccess',
                'filePath'    => $file,
                'line'        => $line,
                'severity'    => Severity::HIGH,
                'confidence'  => Confidence::HIGH,
                'category'    => DetectionCategory::SEO_SPAM,
                'description' => 'A RewriteRule combination targets search engine bots by User-Agent '
                    . 'and redirects them to an external domain, while real visitors see '
                    . 'the normal site. This is cloaking — a black-hat SEO technique.',
                'explanation' => 'Cloaking serves different content to search engines and human '
                    . 'visitors. By detecting Google, Bing, Yahoo, and other bot User-Agents '
                    . 'via RewriteCond, the attacker redirects the bots to an external spam '
                    . 'or malware site for SEO link injection, while human visitors see '
                    . 'the normal WordPress site and remain unaware of the compromise. '
                    . 'This poisons the site\'s search ranking and spreads spam.',
                'remediation' => 'Remove the malicious RewriteCond/RewriteRule block. '
                    . 'Check other .htaccess files on the server for similar patterns. '
                    . 'Audit Google Search Console for unexpected redirect reports.',
                'evidence'    => [
                    $this->makeEvidence(
                        $this->offsetToLine($content, $botMatch[0][1]),
                        $this->lineSnippet($content, $this->offsetToLine($content, $botMatch[0][1])),
                        'Bot User-Agent condition: ' . trim($botMatch[0][0]),
                    ),
                    $this->makeEvidence(
                        $this->offsetToLine($content, $redirMatch[0][1]),
                        $this->lineSnippet($content, $this->offsetToLine($content, $redirMatch[0][1])),
                        'External redirect rule: ' . trim($redirMatch[0][0]),
                    ),
                ],
                'tags'        => ['htaccess', 'cloaking', 'seo-spam', 'redirect'],
            ]);
        }

        // ── HTAC-004: All-traffic unconditional external redirect ─────────────
        // "Redirect 301 / http://external-domain" hijacks the entire site.
        // Target path must be exactly "/" (root) to avoid flagging path-specific
        // redirects that may be legitimate (e.g. moved resources).
        if (preg_match(
            '/^\s*Redirect\s+30[12]\s+\/\s+https?:\/\//im',
            $content, $m, PREG_OFFSET_CAPTURE,
        )) {
            $line = $this->offsetToLine($content, $m[0][1]);
            $findings[] = Finding::create([
                'ruleId'      => 'HTAC-004',
                'title'       => 'All-traffic redirect to external domain',
                'filePath'    => $file,
                'line'        => $line,
                'severity'    => Severity::HIGH,
                'confidence'  => Confidence::HIGH,
                'category'    => DetectionCategory::REDIRECT,
                'description' => sprintf(
                    'The directive "%s" redirects all site visitors to an external domain.',
                    trim($m[0][0]),
                ),
                'explanation' => 'A Redirect directive targeting the root path (/) with a 301/302 '
                    . 'status code sends every visitor to an external URL. This is used by '
                    . 'attackers to silently hijack a WordPress site\'s traffic — all visitors '
                    . 'are sent to a spam, phishing, or malware distribution site. '
                    . 'Legitimate HTTPS upgrade redirects target the same domain; '
                    . 'cross-domain root redirects are almost never intentional.',
                'remediation' => 'Remove this Redirect directive immediately. '
                    . 'Check all .htaccess files for similar redirects. '
                    . 'Review server access logs to understand the impact.',
                'evidence'    => [
                    $this->makeEvidence($line, $this->lineSnippet($content, $line), trim($m[0][0])),
                ],
                'tags'        => ['htaccess', 'redirect', 'traffic-hijack'],
            ]);
        }

        // ── HTAC-005: ExecCGI enabled ─────────────────────────────────────────
        // Options +ExecCGI allows the server to execute CGI scripts in this
        // directory. Combined with AddHandler, arbitrary files can be run as
        // executables. Almost never needed in a WordPress installation.
        if (preg_match(
            '/^\s*Options\s+.*\+ExecCGI/im',
            $content, $m, PREG_OFFSET_CAPTURE,
        )) {
            $line = $this->offsetToLine($content, $m[0][1]);
            $findings[] = Finding::create([
                'ruleId'      => 'HTAC-005',
                'title'       => 'CGI execution enabled via Options +ExecCGI',
                'filePath'    => $file,
                'line'        => $line,
                'severity'    => Severity::HIGH,
                'confidence'  => Confidence::MEDIUM,
                'category'    => DetectionCategory::BACKDOOR,
                'description' => sprintf(
                    '"%s" enables CGI execution for this directory. '
                    . 'Combined with AddHandler, any file can be made executable as a CGI script.',
                    trim($m[0][0]),
                ),
                'explanation' => 'Options +ExecCGI instructs Apache to allow CGI execution '
                    . 'in this directory. An attacker who can also set AddHandler cgi-script '
                    . 'for a file extension can then upload and execute arbitrary binaries '
                    . 'or scripts. This capability is not required by any standard WordPress '
                    . 'plugin or theme and should not appear in a WP .htaccess file.',
                'remediation' => 'Remove +ExecCGI from the Options directive. '
                    . 'Verify whether CGI is needed at the server configuration level '
                    . 'and restrict it appropriately.',
                'evidence'    => [
                    $this->makeEvidence($line, $this->lineSnippet($content, $line), trim($m[0][0])),
                ],
                'tags'        => ['htaccess', 'exec-cgi', 'backdoor'],
            ]);
        }

        // ── HTAC-006: PHP engine re-enabled in uploads or arbitrary directory ──
        // "php_flag engine on" enables PHP execution where it was previously
        // disabled. Most suspicious in wp-content/uploads/ where WordPress
        // places a .htaccess specifically to BLOCK PHP execution.
        if (preg_match(
            '/^\s*php_flag\s+engine\s+on/im',
            $content, $m, PREG_OFFSET_CAPTURE,
        )) {
            $line     = $this->offsetToLine($content, $m[0][1]);
            $inUploads = str_contains(str_replace('\\', '/', $file), 'wp-content/uploads');
            $severity  = $inUploads ? Severity::CRITICAL : Severity::HIGH;
            $uploadsNote = $inUploads
                ? ' This file is inside wp-content/uploads/, which WordPress deliberately '
                  . 'protects with a .htaccess that DISABLES PHP. Re-enabling it here '
                  . 'is a direct bypass of that protection.'
                : '';

            $findings[] = Finding::create([
                'ruleId'      => 'HTAC-006',
                'title'       => 'PHP engine re-enabled via php_flag engine on',
                'filePath'    => $file,
                'line'        => $line,
                'severity'    => $severity,
                'confidence'  => Confidence::HIGH,
                'category'    => DetectionCategory::BACKDOOR,
                'description' => '"php_flag engine on" re-enables PHP script execution '
                    . 'for this directory.' . $uploadsNote,
                'explanation' => 'php_flag engine on overrides a php_flag engine off directive '
                    . 'set at a higher directory level. WordPress ships with a .htaccess '
                    . 'in wp-content/uploads/ that sets engine off specifically to prevent '
                    . 'uploaded files from being executed as PHP. Placing a new .htaccess '
                    . 'with engine on in a subdirectory bypasses this protection, allowing '
                    . 'any uploaded PHP file in that subdirectory to execute.',
                'remediation' => 'Remove this .htaccess file or delete the php_flag engine on '
                    . 'directive. Verify the parent directory .htaccess still contains '
                    . 'php_flag engine off. Audit the directory for PHP files.',
                'evidence'    => [
                    $this->makeEvidence($line, $this->lineSnippet($content, $line), trim($m[0][0])),
                ],
                'tags'        => ['htaccess', 'php-engine', 'bypass', 'uploads'],
            ]);
        }

        return $findings;
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /**
     * Convert a byte offset in $content to a 1-based line number.
     */
    private function offsetToLine(string $content, int $offset): int
    {
        return substr_count($content, "\n", 0, $offset) + 1;
    }

    /**
     * Return the full text of a specific line (1-based) from $content.
     */
    private function lineSnippet(string $content, int $lineNumber): string
    {
        $lines = explode("\n", $content);
        return trim($lines[$lineNumber - 1] ?? '');
    }
}
