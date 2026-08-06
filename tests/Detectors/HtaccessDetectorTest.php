<?php

declare(strict_types=1);

namespace Wpma\Tests\Detectors;

use PHPUnit\Framework\TestCase;
use Wpma\Detectors\HtaccessDetector;
use Wpma\Models\AnalysisObject;
use Wpma\Models\FileFeatures;
use Wpma\Models\FileMeta;
use Wpma\Models\Severity;

/**
 * Tests for HtaccessDetector.
 *
 * Apache directive strings are used directly in rawContent — they are
 * configuration syntax, not executable code, and carry no AV risk.
 */
final class HtaccessDetectorTest extends TestCase
{
    private HtaccessDetector $detector;

    protected function setUp(): void
    {
        parent::setUp();
        $this->detector = new HtaccessDetector();
    }

    // ── isApplicable ──────────────────────────────────────────────────────────

    public function testIsApplicableForHtaccess(): void
    {
        $ao = $this->makeAo('', '/var/www/html/.htaccess');
        $this->assertTrue($this->detector->isApplicable($ao));
    }

    public function testIsNotApplicableForPhpFile(): void
    {
        $ao = $this->makeAo('', '/var/www/html/index.php');
        $this->assertFalse($this->detector->isApplicable($ao));
    }

    public function testIsNotApplicableForOtherConfigFile(): void
    {
        $ao = $this->makeAo('', '/var/www/html/nginx.conf');
        $this->assertFalse($this->detector->isApplicable($ao));
    }

    // ── HTAC-001: PHP handler for arbitrary file types ────────────────────────

    public function testHtac001SetHandlerIsCritical(): void
    {
        $ao = $this->makeAo(
            "Options +FollowSymLinks\nSetHandler application/x-httpd-php\n"
        );

        $findings = $this->detector->detect($ao);

        $this->assertNotEmpty($findings);
        $this->assertSame('HTAC-001', $findings[0]->ruleId);
        $this->assertSame(Severity::CRITICAL, $findings[0]->severity);
    }

    public function testHtac001AddTypeIsCritical(): void
    {
        $ao = $this->makeAo(
            "AddType application/x-httpd-php .jpg .jpeg .png .gif\n"
        );

        $findings = $this->detector->detect($ao);

        $this->assertNotEmpty($findings);
        $this->assertSame('HTAC-001', $findings[0]->ruleId);
        $this->assertSame(Severity::CRITICAL, $findings[0]->severity);
    }

    public function testHtac001AddHandlerIsCritical(): void
    {
        $ao = $this->makeAo(
            "AddHandler application/x-httpd-php .css .js\n"
        );

        $findings = $this->detector->detect($ao);

        $this->assertNotEmpty($findings);
        $this->assertSame('HTAC-001', $findings[0]->ruleId);
    }

    public function testHtac001InsideFilesMatchBlock(): void
    {
        $htaccess = <<<'HTAC'
<FilesMatch "\.(jpg|jpeg|png|gif)$">
SetHandler application/x-httpd-php
</FilesMatch>
HTAC;
        $ao = $this->makeAo($htaccess);

        $findings = $this->detector->detect($ao);

        $this->assertNotEmpty($findings);
        $this->assertSame('HTAC-001', $findings[0]->ruleId);
        $this->assertSame(Severity::CRITICAL, $findings[0]->severity);
    }

    // ── HTAC-002: PHP auto-prepend/append ─────────────────────────────────────

    public function testHtac002AutoPrependFileIsCritical(): void
    {
        $ao = $this->makeAo("php_value auto_prepend_file /var/www/html/malicious.php\n");

        $findings = $this->detector->detect($ao);

        $this->assertNotEmpty($findings);
        $this->assertSame('HTAC-002', $findings[0]->ruleId);
        $this->assertSame(Severity::CRITICAL, $findings[0]->severity);
    }

    public function testHtac002AutoAppendFileIsCritical(): void
    {
        $ao = $this->makeAo("php_value auto_append_file backdoor.php\n");

        $findings = $this->detector->detect($ao);

        $this->assertNotEmpty($findings);
        $this->assertSame('HTAC-002', $findings[0]->ruleId);
        $this->assertSame(Severity::CRITICAL, $findings[0]->severity);
    }

    // ── HTAC-003: Bot-targeting cloaking redirect ─────────────────────────────

    public function testHtac003CloakingRedirectIsHigh(): void
    {
        $htaccess = <<<'HTAC'
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} (Googlebot|bingbot|Yahoo|YahooSeeker)
RewriteRule .* http://malicious-spam.example.com/ [R=302,L]
HTAC;
        $ao = $this->makeAo($htaccess);

        $findings = $this->detector->detect($ao);

        $this->assertNotEmpty($findings);
        $this->assertSame('HTAC-003', $findings[0]->ruleId);
        $this->assertSame(Severity::HIGH, $findings[0]->severity);
    }

    public function testHtac003GenericBotKeywordIsDetected(): void
    {
        $htaccess = <<<'HTAC'
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} (spider|crawl|bot)
RewriteRule ^(.*)$ http://spam-site.example.com/ [R=301,L]
HTAC;
        $ao = $this->makeAo($htaccess);

        $findings = $this->detector->detect($ao);

        $this->assertNotEmpty($findings);
        $this->assertSame('HTAC-003', $findings[0]->ruleId);
    }

    public function testHtac003BotConditionWithoutRedirectNoFinding(): void
    {
        // Bot User-Agent condition is present but no external redirect
        $htaccess = <<<'HTAC'
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} (Googlebot|bingbot)
RewriteRule .* /404 [L]
HTAC;
        $ao = $this->makeAo($htaccess);

        $ruleIds = array_map(fn($f) => $f->ruleId, $this->detector->detect($ao));
        $this->assertNotContains('HTAC-003', $ruleIds,
            'Bot condition without external redirect must not fire HTAC-003');
    }

    public function testHtac003LegitimateHttpsUpgradeNotFlagged(): void
    {
        // This is a standard WordPress HTTPS upgrade pattern — must NOT be flagged
        $htaccess = <<<'HTAC'
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule .* https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
HTAC;
        $ao = $this->makeAo($htaccess);

        $ruleIds = array_map(fn($f) => $f->ruleId, $this->detector->detect($ao));
        $this->assertNotContains('HTAC-003', $ruleIds,
            'HTTPS upgrade redirect must not trigger HTAC-003');
    }

    // ── HTAC-004: All-traffic external redirect ───────────────────────────────

    public function testHtac004Redirect301RootToExternalIsHigh(): void
    {
        $ao = $this->makeAo("Redirect 301 / http://attacker.example.com/\n");

        $findings = $this->detector->detect($ao);

        $this->assertNotEmpty($findings);
        $this->assertSame('HTAC-004', $findings[0]->ruleId);
        $this->assertSame(Severity::HIGH, $findings[0]->severity);
    }

    public function testHtac004Redirect302RootToExternalIsHigh(): void
    {
        $ao = $this->makeAo("Redirect 302 / https://spam.example.com/\n");

        $findings = $this->detector->detect($ao);

        $this->assertNotEmpty($findings);
        $this->assertSame('HTAC-004', $findings[0]->ruleId);
    }

    public function testHtac004PathSpecificRedirectNoFinding(): void
    {
        // Redirecting a specific path is potentially legitimate — must NOT fire
        $ao = $this->makeAo("Redirect 301 /old-page http://example.com/new-page\n");

        $ruleIds = array_map(fn($f) => $f->ruleId, $this->detector->detect($ao));
        $this->assertNotContains('HTAC-004', $ruleIds,
            'Path-specific redirect must not trigger HTAC-004 (only root / redirect does)');
    }

    // ── HTAC-005: ExecCGI enabled ─────────────────────────────────────────────

    public function testHtac005ExecCgiIsHigh(): void
    {
        $ao = $this->makeAo("Options +ExecCGI\nAddHandler cgi-script .py\n");

        $findings = $this->detector->detect($ao);

        $this->assertNotEmpty($findings);
        $this->assertSame('HTAC-005', $findings[0]->ruleId);
        $this->assertSame(Severity::HIGH, $findings[0]->severity);
    }

    public function testHtac005ExecCgiWithOtherOptionsIsDetected(): void
    {
        $ao = $this->makeAo("Options +FollowSymLinks +ExecCGI -Indexes\n");

        $findings = $this->detector->detect($ao);

        $this->assertNotEmpty($findings);
        $this->assertSame('HTAC-005', $findings[0]->ruleId);
    }

    // ── HTAC-006: PHP engine re-enabled ──────────────────────────────────────

    public function testHtac006EngineOnInUploadsIsCritical(): void
    {
        $ao = $this->makeAo(
            "php_flag engine on\n",
            '/var/www/html/wp-content/uploads/revslider/templates/.htaccess',
        );

        $findings = $this->detector->detect($ao);

        $this->assertNotEmpty($findings);
        $this->assertSame('HTAC-006', $findings[0]->ruleId);
        $this->assertSame(Severity::CRITICAL, $findings[0]->severity,
            'php_flag engine on inside uploads must be CRITICAL');
    }

    public function testHtac006EngineOnOutsideUploadsIsHigh(): void
    {
        $ao = $this->makeAo(
            "php_flag engine on\n",
            '/var/www/html/wp-content/plugins/my-plugin/.htaccess',
        );

        $findings = $this->detector->detect($ao);

        $this->assertNotEmpty($findings);
        $this->assertSame('HTAC-006', $findings[0]->ruleId);
        $this->assertSame(Severity::HIGH, $findings[0]->severity,
            'php_flag engine on outside uploads must be HIGH');
    }

    // ── Multiple rules in one file ────────────────────────────────────────────

    public function testMultipleRulesInSameFile(): void
    {
        $htaccess = <<<'HTAC'
# A heavily modified .htaccess
php_value auto_prepend_file /tmp/evil.php
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} (Googlebot|spider)
RewriteRule .* http://spam.example.com/ [R=302,L]
HTAC;
        $ao = $this->makeAo($htaccess);

        $findings   = $this->detector->detect($ao);
        $ruleIds    = array_map(fn($f) => $f->ruleId, $findings);

        $this->assertContains('HTAC-002', $ruleIds, 'auto_prepend_file must be detected');
        $this->assertContains('HTAC-003', $ruleIds, 'cloaking redirect must be detected');
        $this->assertCount(2, $findings, 'Both rules should fire independently');
    }

    // ── Normal WordPress .htaccess produces no findings ───────────────────────

    public function testNormalWordPressHtaccessProducesNoFindings(): void
    {
        $htaccess = <<<'HTAC'
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
HTAC;
        $ao = $this->makeAo($htaccess);

        $this->assertEmpty($this->detector->detect($ao),
            'A standard WordPress .htaccess must produce zero findings');
    }

    public function testUploadPhpBlockHtaccessProducesNoFindings(): void
    {
        // WordPress uploads .htaccess that BLOCKS PHP — should not be flagged
        $htaccess = <<<'HTAC'
# Prevent PHP execution in this directory
<FilesMatch "\.php$">
    Order Deny,Allow
    Deny from all
</FilesMatch>
HTAC;
        $ao = $this->makeAo($htaccess, '/var/www/html/wp-content/uploads/.htaccess');

        $this->assertEmpty($this->detector->detect($ao),
            'The WordPress uploads PHP-blocking .htaccess must produce zero findings');
    }

    public function testEmptyHtaccessProducesNoFindings(): void
    {
        $ao = $this->makeAo('');
        $this->assertEmpty($this->detector->detect($ao));
    }

    // ── Line number accuracy ──────────────────────────────────────────────────

    public function testFindingLineNumberIsCorrect(): void
    {
        $htaccess = "Options +FollowSymLinks\n" // line 1
                  . "RewriteEngine On\n"         // line 2
                  . "php_value auto_prepend_file evil.php\n"; // line 3

        $ao = $this->makeAo($htaccess);

        $findings = $this->detector->detect($ao);
        $htac002  = array_values(array_filter($findings, fn($f) => $f->ruleId === 'HTAC-002'));

        $this->assertNotEmpty($htac002);
        $this->assertSame(3, $htac002[0]->line, 'Line number for HTAC-002 must be 3');
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private function makeAo(
        string $content,
        string $filePath = '/var/www/html/.htaccess',
    ): AnalysisObject {
        $meta = new FileMeta(
            filePath:     $filePath,
            relativePath: basename($filePath),
            fileSize:     strlen($content),
            extension:    '',
            encoding:     'UTF-8',
            lineCount:    max(1, substr_count($content, "\n") + 1),
            scanTimeMs:   0.0,
        );

        return new AnalysisObject(
            meta:          $meta,
            rawContent:    $content,
            tokens:        [],
            functionCalls: [],
            strings:       [],
            variables:     [],
            imports:       [],
            iocs:          [],
            features:      new FileFeatures(),
            parseErrors:   [],
        );
    }
}
