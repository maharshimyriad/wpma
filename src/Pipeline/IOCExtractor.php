<?php

declare(strict_types=1);

namespace Wpma\Pipeline;

use Wpma\Models\IOC;
use Wpma\Models\IOCType;

/**
 * IOCExtractor — extracts Indicators of Compromise from raw PHP/HTML source.
 */
class IOCExtractor
{
    private const KNOWN_WP_DOMAINS = [
        // WordPress core services
        'wordpress.org', 'wordpress.com', 'wp.com', 'wpengine.com',
        'gravatar.com', 'automattic.com', 'akismet.com', 'jetpack.com',
        // Google
        'google.com', 'googleapis.com', 'gstatic.com', 'googletagmanager.com',
        'google-analytics.com', 'googleusercontent.com', 'fonts.googleapis.com',
        'fonts.gstatic.com', 'accounts.google.com',
        // CDN / JS libraries
        'jquery.com', 'cdnjs.cloudflare.com', 'cdn.jsdelivr.net', 'unpkg.com',
        'bootstrapcdn.com', 'cloudflare.com',
        // Social / tracking
        'facebook.com', 'fbcdn.net', 'connect.facebook.net',
        'twitter.com', 'platform.twitter.com', 'youtube.com',
        'linkedin.com', 'instagram.com',
        'clarity.ms', 'bat.bing.com',
        // Shopify
        'shopify.com', 'myshopify.com', 'shopifycdn.com', 'shopifycloud.com',
        'shopifysvc.com', 'monorail-edge.shopifysvc.com',
        // AMP
        'ampproject.org', 'cdn.ampproject.org',
        // Popular WP plugin / theme vendors
        'wpbeaverbuilder.com', 'elementor.com', 'yoast.com', 'rankmath.com',
        'wordfence.com', 'sucuri.net', 'woocommerce.com', 'woothemes.com',
        'ithemes.com', 'wpforms.com', 'gravityforms.com', 'awesomemotive.com',
        'advancedcustomfields.com', 'wpallimport.com', 'wpbakery.com',
        'divi.com', 'avada.io', 'genesis.com', 'studiopress.com',
        'wpml.org', 'polylang.pro',
        'updraftplus.com', 'backwpup.de', 'duplicator.com',
        'smushpro.wpmudev.org', 'wpmudev.org',
        // Developer / standards resources — should NEVER be flagged as IOCs
        'php.net', 'composer.org', 'packagist.org', 'getcomposer.org',
        'github.com', 'raw.githubusercontent.com', 'gitlab.com',
        'w3.org', 'www.w3.org',          // W3C standards
        'ietf.org', 'www.ietf.org',      // IETF RFCs
        'iana.org', 'www.iana.org',      // IANA
        'mozilla.org', 'developer.mozilla.org', // MDN
        'php.net', 'www.php.net',        // PHP documentation
        'schema.org', 'www.schema.org',  // Schema.org structured data
        'example.com', 'example.org',    // RFC example domains
        'json-schema.org',               // JSON Schema
        'openssl.org',                   // OpenSSL
        // Payment
        'paypal.com', 'stripe.com', 'braintreepayments.com', 'authorize.net',
        // Email services
        'mailchimp.com', 'list-manage.com', 'sendgrid.com', 'mailgun.com',
    ];

    // Patterns that look like IP addresses but are actually version numbers
    // e.g. 1.6.4.3, 2.5.0.1 — all octets < 20 in a comment or string context
    private const VERSION_NUMBER_PATTERN = '/^(?:[0-9]|1[0-9])\.(?:[0-9]|[1-9][0-9])\.(?:[0-9]|[1-9][0-9])\.(?:[0-9]|[1-9][0-9])$/';

    private const PRIVATE_IP_RANGES = [
        '/^10\./', '/^172\.(1[6-9]|2\d|3[01])\./',
        '/^192\.168\./', '/^127\./', '/^::1$/', '/^localhost$/i',
    ];

    /** @return IOC[] */
    public function extract(string $rawContent, string $filePath): array
    {
        $iocs = [];
        $seen = [];

        $add = function (IOCType $type, string $value, int $line) use (&$iocs, &$seen, $filePath): void {
            $key = $type->value . ':' . $value;
            if (isset($seen[$key])) {
                return;
            }
            $seen[$key] = true;

            $isPrivate       = $this->isPrivateIp($value);
            $isKnownWp       = $this->isKnownWpService($value);

            $iocs[] = new IOC(
                type:              $type,
                value:             $value,
                filePath:          $filePath,
                line:              $line,
                isPrivateIp:       $isPrivate,
                isKnownWpService:  $isKnownWp,
            );
        };

        $lines = explode("\n", $rawContent);

        foreach ($lines as $lineNum => $line) {
            $lineNo = $lineNum + 1;

            // URLs (http/https)
            if (preg_match_all('#https?://[^\s\'"<>)}\]]+#', $line, $m)) {
                foreach ($m[0] as $url) {
                    $url = rtrim($url, '.,;\'")');
                    $add(IOCType::URL, $url, $lineNo);

                    // Also extract domain
                    $host = parse_url($url, PHP_URL_HOST);
                    if ($host) {
                        $add(IOCType::DOMAIN, $host, $lineNo);
                    }
                }
            }

            // IPv4 addresses — skip version numbers like 1.6.4.3
            if (preg_match_all('/\b(\d{1,3}\.){3}\d{1,3}\b/', $line, $m)) {
                foreach ($m[0] as $ip) {
                    if ($this->isValidIpv4($ip) && !$this->looksLikeVersionNumber($ip)) {
                        $add(IOCType::IP, $ip, $lineNo);
                    }
                }
            }

            // Email addresses
            if (preg_match_all('/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/', $line, $m)) {
                foreach ($m[0] as $email) {
                    $add(IOCType::EMAIL, $email, $lineNo);
                }
            }

            // Telegram Bot tokens: digits:alphanum35
            if (preg_match_all('/\b\d{8,12}:[A-Za-z0-9_\-]{35}\b/', $line, $m)) {
                foreach ($m[0] as $token) {
                    $add(IOCType::TELEGRAM_TOKEN, $token, $lineNo);
                }
            }

            // Discord webhook URLs
            if (preg_match_all('#https://discord(?:app)?\.com/api/webhooks/\d+/[\w\-]+#', $line, $m)) {
                foreach ($m[0] as $webhook) {
                    $add(IOCType::DISCORD_WEBHOOK, $webhook, $lineNo);
                }
            }

            // JWT tokens (3 base64url segments separated by dots)
            if (preg_match_all('/eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/', $line, $m)) {
                foreach ($m[0] as $jwt) {
                    $add(IOCType::JWT, $jwt, $lineNo);
                }
            }

            // Large base64 blobs (≥50 chars)
            if (preg_match_all('/[A-Za-z0-9+\/]{50,}={0,2}/', $line, $m)) {
                foreach ($m[0] as $blob) {
                    // Avoid flagging URLs and known tokens
                    if (!str_contains($blob, '://') && !str_contains($blob, '.')) {
                        $add(IOCType::BASE64_BLOB, $blob, $lineNo);
                    }
                }
            }

        // Large hex blobs (≥64 hex chars) — only flag if NOT a known hash length
        // MD5=32, SHA1=40, SHA256=64, SHA512=128 are legitimate security hashes
        if (preg_match_all('/\b[0-9a-fA-F]{64,}\b/', $line, $m)) {
            foreach ($m[0] as $hex) {
                $len = strlen($hex);
                // Skip known hash lengths used by security plugins (integrity checking)
                if ($len === 64 || $len === 128 || $len === 40 || $len === 32) {
                    // These are SHA256/SHA512/SHA1/MD5 — add as FILE_HASH, not HEX_BLOB
                    $add(IOCType::FILE_HASH, $hex, $lineNo);
                    continue;
                }
                // Only flag as hex blob if it's an unusual length (likely payload)
                $add(IOCType::HEX_BLOB, $hex, $lineNo);
            }
        }
        }

        return $iocs;
    }

    private function isValidIpv4(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }

    /**
     * Returns true if the IP-like string is probably a version number.
     * Version numbers: all octets are typically < 20, and max octet < 50.
     * Real IPs frequently have octets > 50.
     */
    private function looksLikeVersionNumber(string $ip): bool
    {
        $parts = explode('.', $ip);
        if (count($parts) !== 4) {
            return false;
        }
        // If all parts are < 30, it's likely a version number like 1.6.4.3
        $allSmall = true;
        foreach ($parts as $part) {
            if ((int)$part >= 30) {
                $allSmall = false;
                break;
            }
        }
        return $allSmall;
    }

    private function isPrivateIp(string $value): bool
    {
        foreach (self::PRIVATE_IP_RANGES as $pattern) {
            if (preg_match($pattern, $value)) {
                return true;
            }
        }
        return false;
    }

    private function isKnownWpService(string $value): bool
    {
        $host = parse_url($value, PHP_URL_HOST) ?: $value;
        $host = strtolower($host);

        foreach (self::KNOWN_WP_DOMAINS as $known) {
            if ($host === $known || str_ends_with($host, '.' . $known)) {
                return true;
            }
        }
        return false;
    }
}
