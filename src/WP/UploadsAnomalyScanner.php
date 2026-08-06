<?php

declare(strict_types=1);

namespace Wpma\WP;

use Wpma\Models\Confidence;
use Wpma\Models\DetectionCategory;
use Wpma\Models\Finding;
use Wpma\Models\Severity;

/**
 * UploadsAnomalyScanner — scans the WordPress uploads directory for files that
 * should never exist there: PHP code, executables, archives, and scripts.
 *
 * The uploads directory is intended exclusively for media files (images, video,
 * audio, documents). Any executable or archive found there is a strong indicator
 * of a compromised site, regardless of what the file is named.
 *
 * Detection strategy:
 *   1. Files with dangerous extensions (.php, .sh, .exe, …) are flagged immediately.
 *   2. Files with safe extensions (images, video, audio, PDFs …) are skipped.
 *   3. Every other file (unknown extension, or NO extension) has its first 8 bytes
 *      read to determine the real content type via magic bytes.
 *
 * This catches the classic attack pattern of dropping an extensionless ZIP or
 * PHP file into a plugin/theme template subdirectory inside uploads (e.g.
 *   wp-content/uploads/revslider/templates/<slug>/c
 * or
 *   wp-content/uploads/revslider/templates/<slug>/s
 * ).
 *
 * Rule IDs:
 *   UPLD-001 — PHP executable content (extension or magic bytes)
 *   UPLD-002 — Archive (ZIP/gzip/RAR/7z) magic bytes
 *   UPLD-003 — Binary executable (ELF/PE) magic bytes
 *   UPLD-004 — Script file (.sh, .py, .rb, .pl, .cgi …)
 */
class UploadsAnomalyScanner
{
    /**
     * Extensions that must never appear in an uploads directory.
     * Matched case-insensitively.
     */
    private const DANGEROUS_PHP_EXTENSIONS = [
        'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'phps', 'pht', 'shtml',
        'asp', 'aspx', 'jsp', 'jspx', 'cfm', 'cfc',
    ];

    private const DANGEROUS_SCRIPT_EXTENSIONS = [
        'sh', 'bash', 'ksh', 'zsh', 'fish',
        'py', 'pyc', 'pyo', 'pyw',
        'rb', 'pl', 'pm',
        'cgi',
        'vbs', 'vbe', 'wsf', 'wsc', 'hta',
        'ps1', 'psm1', 'psd1',
        'bat', 'cmd',
        'exe', 'dll', 'so', 'elf',
        'com', 'scr', 'pif',
    ];

    /**
     * Extensions that are safe in an uploads directory — skip without inspection.
     */
    private const SAFE_EXTENSIONS = [
        // Images
        'jpg', 'jpeg', 'jfif', 'pjp', 'pjpeg', 'png', 'gif', 'bmp', 'webp',
        'ico', 'cur', 'svg', 'svgz', 'tiff', 'tif', 'heic', 'heif', 'avif',
        'jxl', 'apng',
        // Video
        'mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv', 'webm', 'm4v', 'ogv',
        '3gp', '3g2', 'mpg', 'mpeg', 'f4v', 'divx', 'xvid', 'ts', 'm2ts',
        // Audio
        'mp3', 'wav', 'ogg', 'flac', 'm4a', 'aac', 'wma', 'opus',
        'mid', 'midi', 'ra', 'rm', 'aiff', 'aif', 'au',
        // Documents
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'odt', 'ods', 'odp', 'odg', 'odf',
        'txt', 'rtf', 'csv', 'epub', 'mobi', 'azw', 'azw3', 'djvu',
        // Fonts
        'woff', 'woff2', 'ttf', 'eot', 'otf', 'fon', 'fnt',
        // Data / structured text
        'json', 'xml', 'xsl', 'xsd', 'rss', 'atom', 'yaml', 'yml',
        // Miscellaneous safe types
        'ics', 'vcf', 'kml', 'kmz', 'gpx',
        // WordPress / GD thumbnail meta (no content risk)
        'nfo',
    ];

    /**
     * Scan the uploads directory for anomalous files.
     *
     * Runs its own recursive enumeration — independent of FileDiscovery and the
     * shell-wrapper file lists — so extensionless archives and PHP files are always
     * found even when they do not appear in the PHP-only find output.
     *
     * @param  string $uploadsDir  Absolute path to the uploads directory (no trailing slash)
     * @return array<string, Finding[]>  Absolute file path → array of findings
     */
    public function scan(string $uploadsDir): array
    {
        $uploadsDir = rtrim(str_replace('\\', '/', $uploadsDir), '/');
        $results    = [];
        $stack      = [$uploadsDir];

        while (!empty($stack)) {
            $current = array_pop($stack);
            $entries = @scandir($current) ?: [];

            foreach ($entries as $entry) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }

                $full = $current . '/' . $entry;

                // Ignore symlinks in uploads — should not exist
                if (is_link($full)) {
                    continue;
                }

                if (is_dir($full)) {
                    $stack[] = $full;
                    continue;
                }

                if (!is_file($full) || !is_readable($full)) {
                    continue;
                }

                $ext     = strtolower(pathinfo($full, PATHINFO_EXTENSION));
                $relPath = ltrim(substr(str_replace('\\', '/', $full), strlen($uploadsDir)), '/');

                // ── Fast path: known-safe extension ──────────────────────────────
                if (in_array($ext, self::SAFE_EXTENSIONS, true)) {
                    continue;
                }

                // ── Dangerous PHP/server extension ────────────────────────────────
                if (in_array($ext, self::DANGEROUS_PHP_EXTENSIONS, true)) {
                    $results[$full][] = $this->makePhpExtensionFinding($full, $relPath, $ext);
                    continue;
                }

                // ── Dangerous script/binary extension ─────────────────────────────
                if (in_array($ext, self::DANGEROUS_SCRIPT_EXTENSIONS, true)) {
                    $results[$full][] = $this->makeScriptExtensionFinding($full, $relPath, $ext);
                    continue;
                }

                // ── Unknown or no extension: inspect magic bytes ──────────────────
                $contentType = $this->sniffContentType($full);

                if ($contentType !== 'unknown') {
                    $results[$full][] = $this->makeMagicBytesFinding($full, $relPath, $contentType);
                }
            }
        }

        return $results;
    }

    // ── Content-type detection ─────────────────────────────────────────────────

    /**
     * Read the first 8 bytes of a file and determine its real content type.
     *
     * Returns one of: 'php', 'archive', 'binary', or 'unknown'.
     * 'unknown' means the file is likely plain text or an unrecognised format.
     */
    private function sniffContentType(string $absPath): string
    {
        $header = @file_get_contents($absPath, false, null, 0, 8);
        if ($header === false || $header === '') {
            return 'unknown';
        }

        // PHP open tags — code disguised as a different file type
        if (str_starts_with($header, '<?php') || str_starts_with($header, '<?=')) {
            return 'php';
        }

        // ZIP / PKZIP: PK\x03\x04
        if (str_starts_with($header, "PK\x03\x04")) {
            return 'archive';
        }

        // gzip: \x1f\x8b
        if (str_starts_with($header, "\x1f\x8b")) {
            return 'archive';
        }

        // RAR: Rar!
        if (str_starts_with($header, 'Rar!')) {
            return 'archive';
        }

        // 7-zip: 7z\xbc\xaf
        if (str_starts_with($header, "7z\xbc\xaf")) {
            return 'archive';
        }

        // ELF binary (Linux/Unix executable / shared object)
        if (str_starts_with($header, "\x7fELF")) {
            return 'binary';
        }

        // PE binary (Windows .exe / .dll)
        if (str_starts_with($header, 'MZ')) {
            return 'binary';
        }

        return 'unknown';
    }

    // ── Finding factories ──────────────────────────────────────────────────────

    private function makePhpExtensionFinding(string $absPath, string $relPath, string $ext): Finding
    {
        return Finding::create([
            'ruleId'      => 'UPLD-001',
            'title'       => sprintf('Executable file in uploads directory: %s', $relPath),
            'filePath'    => $absPath,
            'line'        => 0,
            'severity'    => Severity::MEDIUM,
            'confidence'  => Confidence::HIGH,
            'category'    => DetectionCategory::FILE_MANIPULATION,
            'description' => sprintf(
                'A PHP or server-executable file (%s) was found at "%s" inside the WordPress uploads directory. '
                . 'WPMA did not detect suspicious behavior in this file during behavioral analysis.',
                $ext,
                $relPath,
            ),
            'explanation' => 'Some plugins legitimately create PHP placeholder or protection files in uploads, '
                . 'and empty or defensive files can be benign. However, executable files are unusual in the uploads '
                . 'directory and should be reviewed to confirm they were created intentionally.',
            'remediation' => 'Review this file and confirm why executable code is present in uploads. '
                . 'If it is not expected, remove it and investigate how it was created.',
            'evidence'    => [],
            'tags'        => ['uploads', 'php-in-uploads', 'wp-uploads-anomaly', $ext],
        ]);
    }

    private function makeScriptExtensionFinding(string $absPath, string $relPath, string $ext): Finding
    {
        $isBinary = in_array($ext, ['exe', 'dll', 'so', 'elf', 'com', 'scr', 'pif'], true);
        $severity = $isBinary ? Severity::CRITICAL : Severity::HIGH;
        $ruleId   = $isBinary ? 'UPLD-003' : 'UPLD-004';
        $typeLabel = $isBinary ? 'binary executable' : 'script file';

        return Finding::create([
            'ruleId'      => $ruleId,
            'title'       => sprintf('Unexpected %s in uploads directory: %s', $typeLabel, $relPath),
            'filePath'    => $absPath,
            'line'        => 0,
            'severity'    => $severity,
            'confidence'  => Confidence::HIGH,
            'category'    => DetectionCategory::FILE_MANIPULATION,
            'description' => sprintf(
                'A %s (%s) was found at "%s" inside the WordPress uploads directory.',
                $typeLabel,
                $ext,
                $relPath,
            ),
            'explanation' => sprintf(
                'An uploads directory should never contain %ss. '
                . 'This file type is not a valid WordPress media upload and suggests either '
                . 'a compromised upload handler or a direct server-level file write by an attacker.',
                $typeLabel,
            ),
            'remediation' => 'Delete this file immediately and review server access logs.',
            'evidence'    => [],
            'tags'        => ['uploads', 'wp-uploads-anomaly', $typeLabel, $ext],
        ]);
    }

    private function makeMagicBytesFinding(string $absPath, string $relPath, string $contentType): Finding
    {
        [$ruleId, $severity, $typeLabel] = match ($contentType) {
            'php'     => ['UPLD-001', Severity::MEDIUM, 'PHP code (extensionless)'],
            'binary'  => ['UPLD-003', Severity::CRITICAL, 'binary executable (extensionless)'],
            'archive' => ['UPLD-002', Severity::HIGH,     'archive file (extensionless)'],
            default   => ['UPLD-002', Severity::MEDIUM,   'unknown binary content'],
        };

        $archiveNote = $contentType === 'archive'
            ? ' Archives planted in the uploads directory are a well-known malware staging '
              . 'technique — the ZIP typically contains an obfuscated PHP payload that '
              . 'downloads further content from an attacker-controlled server and writes it '
              . 'to a new .php file. The ZIP magic bytes (PK\\x03\\x04) confirm archive content '
              . 'despite the missing or misleading file extension.'
            : '';

        if ($contentType === 'php') {
            return Finding::create([
                'ruleId'      => $ruleId,
                'title'       => sprintf('Executable file in uploads directory: %s', $relPath),
                'filePath'    => $absPath,
                'line'        => 0,
                'severity'    => $severity,
                'confidence'  => Confidence::HIGH,
                'category'    => DetectionCategory::FILE_MANIPULATION,
                'description' => sprintf(
                    'File "%s" in the WordPress uploads directory was identified as %s by its file header (magic bytes). '
                    . 'WPMA did not detect suspicious behavior in this file during behavioral analysis.',
                    $relPath,
                    $typeLabel,
                ),
                'explanation' => 'Some plugins legitimately create PHP placeholder or protection files in uploads, '
                    . 'and empty or defensive files can be benign. However, executable files are unusual in the uploads '
                    . 'directory and should be reviewed to confirm they were created intentionally.',
                'remediation' => 'Review this file and confirm why executable code is present in uploads. '
                    . 'If it is not expected, remove it and investigate how it was created.',
                'evidence'    => [],
                'tags'        => ['uploads', 'wp-uploads-anomaly', 'magic-bytes', $contentType],
            ]);
        }

        return Finding::create([
            'ruleId'      => $ruleId,
            'title'       => sprintf('Suspicious %s in uploads directory: %s', $typeLabel, $relPath),
            'filePath'    => $absPath,
            'line'        => 0,
            'severity'    => $severity,
            'confidence'  => Confidence::HIGH,
            'category'    => DetectionCategory::FILE_MANIPULATION,
            'description' => sprintf(
                'File "%s" in the WordPress uploads directory was identified as %s '
                . 'by its file header (magic bytes). The file has no recognised media extension.',
                $relPath,
                $typeLabel,
            ),
            'explanation' => sprintf(
                'Magic-byte analysis confirmed this file contains %s content despite '
                . 'having no matching extension — a deliberate obfuscation technique.%s '
                . 'The uploads directory should contain only media files.',
                $typeLabel,
                $archiveNote,
            ),
            'remediation' => 'Inspect the file contents immediately. '
                . 'If it is a ZIP, extract and examine its contents for PHP or other executable code. '
                . 'Delete the file if it is not a legitimate media upload. '
                . 'Review server access logs to determine how it was written.',
            'evidence'    => [],
            'tags'        => ['uploads', 'wp-uploads-anomaly', 'magic-bytes', $contentType],
        ]);
    }
}
