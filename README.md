# WPMA

WPMA is a command-line tool for scanning WordPress installations, plugins, themes, uploads directories, individual files, and generic directories for malware-related behavior and integrity issues.

It combines WordPress integrity verification with deeper per-file malware analysis so that unchanged official files can be treated differently from modified or unexpected local files.

## Overview

WPMA is designed for WordPress malware triage and investigation.

At a high level, it does two complementary things:

- **Integrity verification** checks WordPress core and WordPress.org plugins against official checksums.
- **Malware analysis** inspects file content for suspicious behaviors such as backdoors, droppers, SEO spam, malicious redirects, credential theft, and dangerous `.htaccess` directives.

In its default **smart scan** mode, WPMA uses integrity results to avoid unnecessary deep analysis of verified official files while keeping modified or unexpected files eligible for deeper inspection. For normal WordPress site scans and plugins-directory scans, plugins that do not have an official WordPress.org integrity source are reported as **Unverified [premium/custom]** and excluded from behavioral malware analysis for that plugin directory.

## Key features

Verified from the current implementation:

- WordPress target auto-detection for:
  - full WordPress sites
  - WordPress core
  - `wp-content/plugins`
  - a single plugin directory
  - `wp-content/themes`
  - a single theme directory
  - uploads directories
  - single files
  - generic directories
- Smart scan mode with integrity-first candidate reduction
- Quick integrity-only mode (`--quick`)
- Full deep-scan mode (`--full`)
- Shell-accelerated indexing and pattern filtering via `wpma.sh` when `find` and `grep` are available
- WordPress core checksum verification using the official WordPress.org core checksums API
- Plugin integrity verification using the WordPress.org plugin checksum API, with a WP-CLI fallback path in the plugin checker
- Premium/custom plugin classification when no official WordPress.org integrity source is available, with clear reporting and skipped behavioral malware analysis during normal site/plugins-directory scans
- Uploads anomaly scanning for PHP files, archives, executables, and scripts inside `wp-content/uploads`
- Behavioral detectors for:
  - command execution and dangerous backdoor sinks
  - dynamic callback abuse
  - dynamic PHP execution (`eval` / `assert`) with provenance checks
  - malicious redirects and credential exfiltration
  - suspicious administrator creation / promotion patterns
  - suspicious `wp_head` / `wp_footer` injection patterns
  - droppers and executable payload writes
  - malicious `.htaccess` directives
  - SEO spam, cloaking, doorway-style injection, and mass content injection
- IOC extraction and reporting
- Text and JSON output
- Severity filtering
- Risk scoring for findings, files, and the overall scan
- PHPUnit test coverage for detectors, pipeline components, reporting, CLI/config, and WordPress integrity checkers

## How detection works

WPMA’s implemented pipeline is:

1. **File discovery / indexing**
2. **Pattern filtering** to identify suspicious candidates
3. **Integrity verification** for supported WordPress components
4. **Smart candidate selection**
5. **Malware analysis** on selected files
6. **Uploads anomaly scanning** (unless disabled)
7. **Risk scoring and report generation**

Per file, the analysis pipeline is:

1. read file
2. detect encoding
3. tokenize PHP
4. extract structured data such as function calls, assignments, variables, imports, and strings
5. extract features
6. extract IOCs
7. assemble an analysis object for detectors

## Detection categories

WPMA currently includes the following detector families and rule prefixes:

| Area | Rule prefixes seen in source | What it covers |
|---|---|---|
| Backdoors / execution | `BACK-*` | Dangerous execution sinks, dynamic PHP execution, dynamic callback abuse, malicious redirects, credential theft, suspicious admin creation/promotion, hook injection |
| Droppers / payload writers | `DROP-*` | Remote payload droppers, decoder-to-writer chains, executable payload writes, uploaded executable placement, suspicious config / `.htaccess` modification |
| SEO spam | `SEO-*` | Gambling/pharma/adult spam, cloaking, hidden links, doorway behavior, suspicious mass post injection |
| `.htaccess` abuse | `HTAC-*` | PHP handler abuse, prepend/append backdoors, cloaking redirects, all-traffic redirects, `ExecCGI`, re-enabling PHP execution |
| Uploads anomalies | `UPLD-*` | PHP files, archives, binaries, and scripts inside uploads |
| Integrity findings | `INTG-*` | Unexpected files, modified official files, missing official files |

Examples verified in source include:

- `BACK-001` dangerous backdoor function usage
- `BACK-007` malicious redirect or credential-theft behaviour
- `DROP-001` remote payload dropper correlation
- `DROP-002` decoded content written to file
- `DROP-003` suspicious executable payload write
- `HTAC-001` through `HTAC-006`
- `SEO-001` through `SEO-008`
- `UPLD-001` through `UPLD-004`
- `INTG-001` through `INTG-003`

## Requirements

From `composer.json` and `wpma.sh`:

### Required

- PHP **8.0+**
- Composer
- PHP CLI
- PHP extensions checked by `wpma.sh check`:
  - `mbstring`
  - `json`
  - `pcre`
  - `tokenizer`

### Optional but supported

- `find` and `grep` for the shell wrapper fast path
- WP-CLI for plugin integrity fallback when the WordPress.org plugin checksum API is unavailable

### Platform notes

- `wpma.sh` is the documented user-facing entry point.
- The wrapper provides shell-side indexing and pre-filtering.
- The wrapper contains Windows/Git Bash path handling, so Windows use is supported in the current implementation.

## Installation

Clone the repository and install dependencies with Composer:

```bash
git clone <repository-url>
cd wpma
composer install
```

Make the wrapper executable:

```bash
chmod +x /path/to/wpma/wpma.sh
```

Add a shell alias in your `~/.bashrc` so you can run WPMA more easily:

```bash
alias wpma='/path/to/wpma/wpma.sh'
```

Reload your shell configuration:

```bash
source ~/.bashrc
```

After that, you can run `wpma` from anywhere on the site without changing into the WPMA directory.

Then verify the environment:

```bash
wpma check
```

If the alias is not available, use the script path directly:

```bash
bash wpma/wpma.sh check
```

And confirm the installed version:

```bash
wpma version
```

Fallback without the alias:

```bash
bash wpma/wpma.sh version
```

## Usage

```bash
wpma help
wpma check
wpma scan [path] [options]
wpma version
```

If the alias is not available, use the full script path directly from anywhere:

```bash
bash wpma/wpma.sh help
bash wpma/wpma.sh check
bash wpma/wpma.sh scan [path] [options]
bash wpma/wpma.sh version
```

### CLI options

Verified from the current parser/help implementation:

| Option | Meaning |
|---|---|
| `--quick` | Integrity check only; skip deep malware scan |
| `--full` | Force deep scan of all files |
| `--no-core` | Skip WordPress core checksum verification |
| `--no-uploads` | Skip uploads anomaly scanning |
| `--full-site` | Force full WordPress site target detection |
| `--core` | Force WordPress core target detection |
| `--plugins` | Force `wp-content/plugins` target detection |
| `--themes` | Force `wp-content/themes` target detection |
| `--file` | Force single-file target detection |
| `--output text` | Text output |
| `--output json` | JSON output |
| `--json` | Shortcut for `--output json` |
| `--output-file <path>` | Write report to a file |
| `--severity <level>` | Minimum severity filter |
| `--no-color` | Disable ANSI colors in text output |
| `--progress` | Show progress output |
| `--quiet` | Suppress progress/status output |
| `--max-file-size <bytes>` | Per-file size limit |
| `--workers <n>` | Worker count setting in config |
| `--rules-dir <path>` | Custom rules directory option accepted by the parser |

Severity levels accepted by the parser are:

```text
info | low | medium | high | critical
```

Internally, findings use the normalized severities:

```text
informational | low | medium | high | critical
```

### Examples

#### Smart scan a WordPress site

```bash
wpma scan /var/www/html
```

#### Force full WordPress site target detection

```bash
wpma scan /var/www/html --full-site
```

#### Scan WordPress core

```bash
wpma scan /var/www/html --core
```

#### Scan all plugins in a site

```bash
wpma scan /var/www/html --plugins
```

#### Scan all themes in a site

```bash
wpma scan /var/www/html --themes
```

#### Scan a single plugin directory

```bash
wpma scan /var/www/html/wp-content/plugins/example-plugin
```

#### Scan a single file

```bash
wpma scan /var/www/html/wp-content/plugins/example-plugin/example.php --file
```

#### Integrity-only scan

```bash
wpma scan /var/www/html --quick
```

#### Full deep scan

```bash
wpma scan /var/www/html --full
```

#### JSON output

```bash
wpma scan /var/www/html --output json
```

#### JSON output to a file

```bash
wpma scan /var/www/html --json --output-file report.json
```

#### Severity filtering

```bash
wpma scan /var/www/html --severity high
```

#### Progress output

```bash
wpma scan /var/www/html --progress
```

#### Quiet mode

```bash
wpma scan /var/www/html --quiet
```

#### Disable ANSI color in text output

```bash
wpma scan /var/www/html --no-color
```

#### Skip core integrity verification

```bash
wpma scan /var/www/html --no-core
```

#### Skip uploads anomaly scanning

```bash
wpma scan /var/www/html --no-uploads
```

## Smart mode

Smart mode is the default behavior.

According to the current implementation, the process is:

1. discover PHP-relevant files
2. pre-filter suspicious candidates
3. run integrity checks where supported
4. reduce deep malware analysis candidates using integrity results

The implemented smart-selection rules are:

- **Verified core files** are removed from deep malware analysis.
- **Verified plugin files** are removed from deep malware analysis.
- **Modified or unexpected files** in verified core/plugins remain eligible for deep analysis.
- **Unverified premium/custom plugins** without an official WordPress.org integrity source are excluded from behavioral malware analysis during normal WordPress site scans and `wp-content/plugins` scans.
- That exclusion applies only to the identified unverified plugin directory; files outside that plugin remain eligible for normal analysis.
- **`--full`** preserves its existing meaning and disables verified-file skipping for components that have official integrity coverage; it does not automatically override the unverified premium/custom plugin behavior.
- **`--quick`** skips the deep malware scan entirely.

The shell wrapper can also precompute:

- a full PHP file list
- a suspicious subset based on grep patterns

That suspicious subset is then passed into the scanner so clean candidates can avoid full deep analysis.

## Integrity checking

### WordPress core

The current implementation verifies WordPress core against the official WordPress.org core checksums API:

```text
https://api.wordpress.org/core/checksums/1.0/?version={version}&locale={locale}
```

Verified scope includes:

- `wp-admin/`
- `wp-includes/`
- a fixed set of root core PHP files such as `wp-load.php`, `wp-login.php`, and `xmlrpc.php`

`wp-content/` is intentionally excluded from core integrity verification.

### Plugins

The plugin checker uses this strategy:

1. WordPress.org plugin checksum API (`sha256` comparison)
2. WP-CLI fallback when the API fails operationally and WP-CLI is available
3. `unavailable` when no official WordPress.org checksum source is available for the plugin
4. `checksum_unavailable` when checksum data cannot be retrieved reliably

The checker enumerates **all local plugin files**, not just PHP files, so extensionless or unexpected files are part of the integrity comparison.

### Integrity result meanings

| Status / condition | Meaning |
|---|---|
| Verified | Local files matched the official manifest |
| Modified | Official files differ from the official release |
| Missing | Files in the official manifest are absent locally |
| Unexpected / extra | Local files exist that are not in the official manifest |
| Unavailable | No official WordPress.org checksum source is available for that plugin; in normal site/plugins scans this is reported as `Unverified [premium/custom]` and behavioral malware analysis is skipped for that plugin directory. This does not mean the plugin is clean, and it does not mean the plugin is malicious. |
| Checksum unavailable | Checksum retrieval failed operationally; this is distinct from a plugin simply not being available from WordPress.org |

## Malware findings

A finding includes, in the current model:

- rule ID
- title
- file path
- line number
- severity
- confidence
- detection category
- description
- explanation
- remediation
- evidence items
- related IOCs
- MITRE technique list
- tags

The text report highlights:

- overall risk score
- per-file risk score
- findings by severity
- finding title and rule ID
- details/description
- remediation/fix guidance
- a final `NOTES` section for suspicious indicators and other report-level coverage notes
- integrity summaries
- warnings

The JSON report includes top-level fields such as:

- `scanId`
- `target`
- `startedAt`
- `completedAt`
- `durationMs`
- `filesScanned`
- `filesSkipped`
- `overallRiskScore`
- `wpmaVersion`
- `fileResults`
- `allIocs`
- `correlations`
- `warnings`
- `pluginIntegrity`

## Example output

Example text output shape, based on the current reporter:

```text
╔══════════════════════════════════════════════╗
║        WPMA v2 — WordPress Malware Scanner   ║
╚══════════════════════════════════════════════╝

SCAN SUMMARY
──────────────────────────────────────────────────
  Target       : /var/www/html
  Files scanned: 128
  Files skipped: 0
  Duration     : 143ms
  Overall Risk : HIGH (62.5/100)

FINDINGS BY SEVERITY
──────────────────────────────────────────────────
  ●  Critical  : 1
  ●  High      : 2
  ●  Medium    : 0
  ●  Low       : 0
  ●  Info      : 0

FINDINGS
──────────────────────────────────────────────────

  📄 wp-content/plugins/example/shell.php  [Risk: 96.0]
     [CRITICAL] Malicious redirect or credential-theft behaviour (line 14)
          Rule    : BACK-007
          Details : This file performs suspicious credential exfiltration behavior with a proven relationship between credential-like input and a specific outbound transmission.
          Fix     : Inspect this outbound transmission immediately.

PLUGIN INTEGRITY
──────────────────────────────────────────────────
  ✔  woocommerce                   Verified v11.0.0 [api]
  ?  premium-plugin                Unverified [premium/custom] v2.1.0
       Official WordPress.org release: Not available
       Malware analysis: Skipped

NOTES
──────────────────────────────────────────────────
  1 premium/custom plugin was not available through the official
  WordPress.org verification source and were excluded from
  behavioral malware analysis.

  WPMA cannot verify the integrity or security of these plugins.
  Review them separately using the original vendor package or
  source.
```

## Exit codes

From the current implementation:

| Code | Meaning |
|---|---|
| `0` | Scan completed and no findings met the output threshold |
| `1` | Scan completed and findings were present |
| `2` | Invalid target, CLI error, or another fatal error |

For `bash wpma.sh check`:

| Code | Meaning |
|---|---|
| `0` | Environment check passed |
| `1` | One or more requirements were missing |

## Project structure

Verified high-level layout:

```text
wpma/
├── composer.json
├── phpunit.xml
├── wpma.php
├── wpma.sh
├── src/
│   ├── Cli/         CLI parsing and target resolution
│   ├── Config/      Scan configuration
│   ├── Detectors/   Malware and integrity rule implementations
│   ├── Engine/      Orchestration, discovery, scoring, progress
│   ├── Intel/       Threat-intel related components
│   ├── Models/      Findings, reports, enums, and analysis data models
│   ├── Pipeline/    Tokenization, extraction, feature and IOC extraction
│   ├── Reporting/   Text and JSON reporters
│   ├── Rules/       Rule-related resources
│   └── WP/          WordPress integrity and uploads-specific logic
└── tests/
    ├── Cli/
    ├── Config/
    ├── Detectors/
    ├── Engine/
    ├── Intel/
    ├── Models/
    ├── Pipeline/
    ├── Reporting/
    └── WP/
```

## Development and testing

### Install dependencies

```bash
composer install
```

### Run the full PHPUnit suite

```bash
vendor/bin/phpunit
```

### Run a focused detector test file

```bash
vendor/bin/phpunit tests/Detectors/DropperDetectorTest.php
```

### Syntax-check a file

```bash
php -l src/Detectors/DropperDetector.php
```

### Check environment through the shell wrapper

```bash
wpma check
```

## Security scope and limitations

- WPMA is a detection and triage tool, not a guarantee that a site is clean.
- Integrity verification and behavioral analysis serve different purposes and are intended to complement each other.
- A verified official file can still matter operationally, but smart mode is intentionally designed to avoid unnecessary deep analysis of unchanged official components.
- Malware findings should be investigated in context before taking action.
- Files outside official checksum ecosystems may not have the same integrity coverage.
- For normal WordPress site scans and plugins-directory scans, a plugin without an official WordPress.org integrity source is reported as `Unverified [premium/custom]` and excluded from behavioral malware analysis for that plugin directory. This is a coverage limitation, not a trust or whitelist decision, and it does not mean the plugin is clean or safe.
- Shell acceleration in `wpma.sh` depends on `find` and `grep`; without them, PHP fallbacks are used.

## License

MIT
