<?php

declare(strict_types=1);

namespace Wpma\Reporting;

use Wpma\Models\ScanReport;
use Wpma\Models\Severity;

class TextReporter implements ReporterInterface
{
    private bool $noColor;

    public function __construct(bool $noColor = false)
    {
        $this->noColor = $noColor;
    }

    public function render(ScanReport $report): string
    {
        $out = [];

        $out[] = $this->line('');
        $out[] = $this->bold('╔══════════════════════════════════════════════╗');
        $out[] = $this->bold('║        WPMA v2 — WordPress Malware Scanner   ║');
        $out[] = $this->bold('╚══════════════════════════════════════════════╝');
        $out[] = '';
        // Summary
        $out[] = $this->bold('SCAN SUMMARY');
        $out[] = str_repeat('─', 50);
        $out[] = sprintf('  Target       : %s', $report->target);
        $out[] = sprintf('  Files scanned: %d', $report->filesScanned);
        $out[] = sprintf('  Files skipped: %d', $report->filesSkipped);
        $out[] = sprintf('  Duration     : %.0fms', $report->durationMs);
        $out[] = sprintf('  Overall Risk : %s', $this->riskLabel($report->overallRiskScore));
        $out[] = '';

        // Count findings by severity
        $counts = [
            'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'informational' => 0,
        ];
        foreach ($report->fileResults as $fr) {
            foreach ($fr->findings as $f) {
                $counts[$f->severity->value]++;
            }
        }

        $out[] = $this->bold('FINDINGS BY SEVERITY');
        $out[] = str_repeat('─', 50);
        $out[] = sprintf('  %s  Critical  : %d', $this->severityColor('critical',    '●'), $counts['critical']);
        $out[] = sprintf('  %s  High      : %d', $this->severityColor('high',        '●'), $counts['high']);
        $out[] = sprintf('  %s  Medium    : %d', $this->severityColor('medium',      '●'), $counts['medium']);
        $out[] = sprintf('  %s  Low       : %d', $this->severityColor('low',         '●'), $counts['low']);
        $out[] = sprintf('  %s  Info      : %d', $this->severityColor('informational','●'), $counts['informational']);
        $out[] = '';

        if ($report->overallRiskScore === 0.0 && array_sum($counts) === 0) {
            $out[] = $this->color('  ✔  No threats detected.', 'green');
            $out[] = '';
            // Still render Plugin Integrity even when no threats found
            $out = array_merge($out, $this->renderPluginIntegrity($report));
            return implode("\n", $out);
        }

        // File results
        $out[] = $this->bold('FINDINGS');
        $out[] = str_repeat('─', 50);

        foreach ($report->fileResults as $fr) {
            if (empty($fr->findings)) continue;

            $out[] = '';
            $out[] = sprintf('  📄 %s  [Risk: %.1f]', $fr->relativePath, $fr->riskScore);

            foreach ($fr->findings as $finding) {
                $sev     = strtoupper($finding->severity->value);
                $sevTag  = $this->severityColor($finding->severity->value, sprintf('[%s]', $sev));
                $out[] = sprintf('     %s %s (line %d)', $sevTag, $finding->title, $finding->line);
                $out[] = sprintf('          Rule    : %s', $finding->ruleId);
                $out[] = sprintf('          Details : %s', $finding->description);
                if ($finding->remediation !== '') {
                    $out[] = sprintf('          Fix     : %s', $finding->remediation);
                }
                $out[] = '';
            }
        }

        // IOCs
        // IOCs — only show suspicious ones (not trusted services, not private IPs)
        $suspiciousIocs = array_filter(
            $report->allIocs,
            fn($ioc) => !$ioc->isKnownWpService
                && !$ioc->isPrivateIp
                && !$this->isTrustedIocDomain($ioc)
        );
        if (!empty($suspiciousIocs)) {
            $out[] = $this->bold('SUSPICIOUS IOCs');
            $out[] = str_repeat('─', 50);
            $shown = 0;
            foreach ($suspiciousIocs as $ioc) {
                if ($shown++ >= 20) {
                    $out[] = sprintf('  ... and %d more', count($suspiciousIocs) - 20);
                    break;
                }
                $out[] = sprintf('  [%s] %s (line %d)', strtoupper($ioc->type->value), $ioc->value, $ioc->line);
            }
            $out[] = '';
        }

        // Plugin Integrity
        $out = array_merge($out, $this->renderPluginIntegrity($report));

        // Warnings
        if (!empty($report->warnings)) {
            $out[] = $this->bold(sprintf('WARNINGS (%d)', count($report->warnings)));
            $out[] = str_repeat('─', 50);
            foreach (array_slice($report->warnings, 0, 10) as $w) {
                $out[] = sprintf('  ⚠  %s', $w->message);
            }
            if (count($report->warnings) > 10) {
                $out[] = sprintf('  ... and %d more', count($report->warnings) - 10);
            }
            $out[] = '';
        }

        return implode("\n", $out);
    }

    private function isTrustedIocDomain(\Wpma\Models\IOC $ioc): bool
    {
        // Filter out domains that are standards/documentation/developer resources
        if ($ioc->type !== \Wpma\Models\IOCType::URL && $ioc->type !== \Wpma\Models\IOCType::DOMAIN) {
            return false;
        }

        $value = $ioc->value;
        $host  = parse_url($value, PHP_URL_HOST) ?: $value;
        $host  = strtolower(trim($host, '.'));

        $trustedSuffixes = [
            'w3.org', 'ietf.org', 'iana.org', 'php.net', 'schema.org',
            'mozilla.org', 'example.com', 'example.org', 'json-schema.org',
            'openssl.org', 'composer.org', 'packagist.org', 'getcomposer.org',
            'github.com', 'gitlab.com', 'bitbucket.org', 'raw.githubusercontent.com',
            'wordpress.org', 'wordpress.com', 'wpbeaverbuilder.com',
            'wordfence.com', 'woocommerce.com', 'yoast.com', 'elementor.com',
        ];

        foreach ($trustedSuffixes as $suffix) {
            if ($host === $suffix || str_ends_with($host, '.' . $suffix)) {
                return true;
            }
        }

        return false;
    }

    private function renderPluginIntegrity(\Wpma\Models\ScanReport $report): array
    {
        if (empty($report->pluginIntegrity)) {
            return [];
        }

        $out = [];
        $out[] = $this->bold('PLUGIN INTEGRITY');
        $out[] = str_repeat('─', 50);

        foreach ($report->pluginIntegrity as $slug => $info) {
            $status  = $info['status'];
            $version = $info['version'] ? " v{$info['version']}" : '';
            $method  = $info['method'] !== 'unavailable' ? " [{$info['method']}]" : '';

            $icon = match ($status) {
                'verified'             => $this->color('✔', 'green'),
                'modified'             => $this->color('✘', 'red'),
                'unavailable',
                'error',
                'checksum_unavailable' => $this->color('?', 'yellow'),
                default                => '·',
            };

            $label = match ($status) {
                'verified'             => $this->color('Verified', 'green'),
                'modified'             => $this->color('MODIFIED', 'red'),
                'unavailable'          => $this->color('Unavailable (premium/custom)', 'yellow'),
                'error'                => $this->color('Check failed', 'yellow'),
                'checksum_unavailable' => $this->color('Checksum API unavailable', 'yellow'),
                default                => $status,
            };

            $out[] = sprintf('  %s  %-30s %s%s%s', $icon, $slug, $label, $version, $method);

            // Show debug stats if available
            if (isset($info['officialCount']) && $info['officialCount'] > 0) {
                $out[] = sprintf(
                    '       Official: %d  Local: %d  OK: %d  Modified: %d  Missing: %d  Extra: %d',
                    $info['officialCount'],
                    $info['localCount'],
                    $info['okCount'],
                    count($info['modifiedFiles']),
                    count($info['missingFiles']),
                    count($info['unexpectedFiles']),
                );
            }

            if ($status === 'modified' && !empty($info['modifiedFiles'])) {
                $out[] = $this->color('       Modified files:', 'red');
                foreach (array_slice($info['modifiedFiles'], 0, 5) as $f) {
                    $out[] = $this->color("         ✘ {$f}", 'red');
                }
                if (count($info['modifiedFiles']) > 5) {
                    $out[] = $this->color('         ... and ' . (count($info['modifiedFiles']) - 5) . ' more', 'red');
                }
            }

            if ($status === 'modified' && !empty($info['unexpectedFiles'])) {
                $out[] = $this->color('       Unexpected/extra files:', 'red');
                foreach (array_slice($info['unexpectedFiles'], 0, 5) as $f) {
                    $out[] = $this->color("         + {$f}", 'red');
                }
                if (count($info['unexpectedFiles']) > 5) {
                    $out[] = $this->color('         ... and ' . (count($info['unexpectedFiles']) - 5) . ' more', 'red');
                }
            }
            if ($status === 'modified' && !empty($info['missingFiles'])) {
                $out[] = $this->color('       Missing official files:', 'yellow');
                foreach (array_slice($info['missingFiles'], 0, 5) as $f) {
                    $out[] = $this->color("         - {$f}", 'yellow');
                }
                if (count($info['missingFiles']) > 5) {
                    $out[] = $this->color('         ... and ' . (count($info['missingFiles']) - 5) . ' more', 'yellow');
                }
            }
        }
        $out[] = '';
        return $out;
    }

    private function riskLabel(float $score): string
    {
        if ($score >= 75) return $this->color(sprintf('CRITICAL (%.1f/100)', $score), 'red');
        if ($score >= 50) return $this->color(sprintf('HIGH (%.1f/100)', $score), 'yellow');
        if ($score >= 25) return $this->color(sprintf('MEDIUM (%.1f/100)', $score), 'cyan');
        if ($score > 0)   return $this->color(sprintf('LOW (%.1f/100)', $score), 'blue');
        return $this->color('CLEAN (0/100)', 'green');
    }

    private function severityColor(string $severity, string $text): string
    {
        return match($severity) {
            'critical'      => $this->color($text, 'red'),
            'high'          => $this->color($text, 'yellow'),
            'medium'        => $this->color($text, 'cyan'),
            'low'           => $this->color($text, 'blue'),
            'informational' => $this->color($text, 'white'),
            default         => $text,
        };
    }

    private function color(string $text, string $color): string
    {
        if ($this->noColor) return $text;
        $codes = [
            'red' => '31', 'green' => '32', 'yellow' => '33',
            'blue' => '34', 'cyan' => '36', 'white' => '37',
            'bold' => '1',
        ];
        $code = $codes[$color] ?? '0';
        return "\033[{$code}m{$text}\033[0m";
    }

    private function bold(string $text): string
    {
        return $this->color($text, 'bold');
    }

    private function line(string $text): string
    {
        return $text;
    }
}
