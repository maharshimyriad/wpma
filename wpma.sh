#!/usr/bin/env bash
# =============================================================================
# WPMA v2 — WordPress Malware Analysis Toolkit
# Shell wrapper — runs find+grep in bash, passes filtered file list to PHP.
# This bypasses PHP's exec() restrictions entirely.
#
# Usage:
#   bash wpma.sh check                     Check environment requirements
#   bash wpma.sh scan /path/to/wordpress   Scan a WordPress installation
#   bash wpma.sh version                   Show version
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHP_ENTRY="${SCRIPT_DIR}/wpma.php"

# ── colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "  ${GREEN}✔${NC}  $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; }
fail() { echo -e "  ${RED}✘${NC}  $*"; }
info() { echo -e "  ${CYAN}→${NC}  $*"; }

WPMA_ACTIVITY_PID=""
WPMA_ACTIVITY_RUNNING=false
WPMA_ACTIVITY_INTERACTIVE=false
WPMA_ACTIVITY_STATUS_FILE=""
WPMA_SCAN_ALL_TMP=""
WPMA_SCAN_SUSPICIOUS_TMP=""

shell_activity_start() {
    local message="$1"
    local interactive="${2:-false}"

    shell_activity_stop

    WPMA_ACTIVITY_INTERACTIVE=false
    [[ "$interactive" == true ]] && WPMA_ACTIVITY_INTERACTIVE=true

    if [[ "$WPMA_ACTIVITY_INTERACTIVE" != true ]]; then
        return
    fi

    WPMA_ACTIVITY_STATUS_FILE=$(mktemp "${TMPDIR:-/tmp}/wpma_status_XXXXXX.txt")
    printf '%s' "$message" > "$WPMA_ACTIVITY_STATUS_FILE"

    WPMA_ACTIVITY_RUNNING=true
    printf '\033[?25l' >&2

    (
        trap '' INT TERM
        local frames=(".  " ".. " "...")
        local index=0
        local line=""

        sleep 0.35
        while [[ -f "$WPMA_ACTIVITY_STATUS_FILE" ]]; do
            line=$(cat "$WPMA_ACTIVITY_STATUS_FILE" 2>/dev/null || printf '%s' "$message")
            printf '\r  %s %s' "$line" "${frames[$index]}" >&2
            sleep 0.25
            index=$(((index + 1) % 3))
        done
    ) &

    WPMA_ACTIVITY_PID=$!
}

shell_activity_update() {
    local message="$1"

    if [[ "$WPMA_ACTIVITY_RUNNING" != true ]] || [[ -z "$WPMA_ACTIVITY_STATUS_FILE" ]]; then
        return
    fi

    printf '%s' "$message" > "$WPMA_ACTIVITY_STATUS_FILE"
}

shell_activity_stop() {
    if [[ -n "$WPMA_ACTIVITY_STATUS_FILE" ]]; then
        rm -f "$WPMA_ACTIVITY_STATUS_FILE" 2>/dev/null || true
        WPMA_ACTIVITY_STATUS_FILE=""
    fi

    if [[ -n "$WPMA_ACTIVITY_PID" ]]; then
        kill "$WPMA_ACTIVITY_PID" 2>/dev/null || true
        wait "$WPMA_ACTIVITY_PID" 2>/dev/null || true
        WPMA_ACTIVITY_PID=""
    fi

    if [[ "$WPMA_ACTIVITY_RUNNING" == true ]] && [[ "$WPMA_ACTIVITY_INTERACTIVE" == true ]]; then
        printf '\r%*s\r' 120 '' >&2
        printf '\033[?25h' >&2
    fi

    WPMA_ACTIVITY_RUNNING=false
    WPMA_ACTIVITY_INTERACTIVE=false
}

cleanup_scan_runtime() {
    shell_activity_stop

    if [[ -n "$WPMA_SCAN_ALL_TMP" || -n "$WPMA_SCAN_SUSPICIOUS_TMP" ]]; then
        rm -f "$WPMA_SCAN_ALL_TMP" "$WPMA_SCAN_SUSPICIOUS_TMP" 2>/dev/null || true
    fi
}

scan_plan_total() {
    local scope="$1"
    local quick_mode="$2"
    local check_core="$3"
    local total=2

    if [[ "$check_core" == true ]] && [[ "$scope" == "site" || "$scope" == "core" ]]; then
        total=$((total + 1))
    fi

    if [[ "$scope" == "site" || "$scope" == "plugins-dir" || "$scope" == "plugin" ]]; then
        total=$((total + 1))
    fi

    if [[ "$quick_mode" == false ]]; then
        total=$((total + 1))
    fi

    printf '%s\n' "$total"
}

resolve_target_path() {
    local input="$1"

    if [[ "$input" =~ ^[a-zA-Z]:[\\/].* ]]; then
        if command -v cygpath &>/dev/null; then
            cygpath -u "$input"
            return
        fi

        printf '%s\n' "${input//\\//}"
        return
    fi

    if [[ -d "$input" ]]; then
        (cd "$input" && pwd)
        return
    fi

    printf '%s/%s\n' "$(cd "$(dirname "$input")" && pwd)" "$(basename "$input")"
}

# Suspicious patterns for grep pre-filter
# Any file matching at least one of these gets deep PHP analysis.
# Files matching NONE are recorded with zero findings (skipped deep scan).
GREP_PATTERNS=(
    'eval\s*\('
    'base64_decode'
    'gzinflate'
    'gzdecode'
    'gzuncompress'
    'str_rot13'
    'shell_exec'
    'system\s*\('
    'exec\s*\('
    'passthru'
    'proc_open'
    'assert\s*\('
    'create_function'
    'togel'
    'slot.online'
    'casino'
    'judi'
    'viagra'
    'cialis'
    'display.:.none'
    'masuk-surga'
    'file_put_contents'
    'move_uploaded_file'
    '\$_POST\['
    '\$_GET\['
    '\$_REQUEST\['
    'href=.*Login'
    'href=.*daftar'
    'href=.*register'
)

# Directories to exclude from scanning
EXCLUDE_DIRS=('.git' 'node_modules' '.svn' 'vendor' '.cache')

# File extensions to scan
FIND_EXTS=('-name' '*.php'
           '-o' '-name' '*.phtml'
           '-o' '-name' '*.php5'
           '-o' '-name' '*.php7'
           '-o' '-name' '*.phar'
           '-o' '-name' '.htaccess')

# =============================================================================
# REQUIREMENT CHECK
# =============================================================================
cmd_check() {
    echo ""
    echo -e "${BOLD}WPMA v2 — Environment Check${NC}"
    echo "$(printf '%.0s─' {1..50})"
    echo ""

    local all_ok=true

    # PHP
    if command -v php &>/dev/null; then
        PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null)
        PHP_MAJ=$(php -r 'echo PHP_MAJOR_VERSION;' 2>/dev/null)
        if [[ "$PHP_MAJ" -ge 8 ]]; then
            ok "PHP ${PHP_VER} (required: 8.0+)"
        else
            fail "PHP ${PHP_VER} — need 8.0 or higher"; all_ok=false
        fi
    else
        fail "PHP not found in PATH"; all_ok=false
    fi

    # Entry point
    if [[ -f "$PHP_ENTRY" ]]; then
        ok "wpma.php found"
    else
        fail "wpma.php not found at: ${PHP_ENTRY}"; all_ok=false
    fi

    # Composer autoloader
    if [[ -f "${SCRIPT_DIR}/vendor/autoload.php" ]]; then
        ok "Composer autoloader present"
    else
        fail "vendor/autoload.php missing — run: composer install"; all_ok=false
    fi

    echo ""
    echo -e "${BOLD}  System Tools (shell fast-path)${NC}"
    echo "  $(printf '%.0s─' {1..40})"

    if command -v find &>/dev/null; then
        ok "find at $(command -v find) — fast file discovery enabled"
    else
        warn "find not available — PHP fallback will be used"
    fi

    if command -v grep &>/dev/null; then
        ok "grep at $(command -v grep) — pre-filtering enabled"
    else
        warn "grep not available — all files will be deep-scanned"
    fi

    echo ""
    echo -e "${BOLD}  PHP Extensions${NC}"
    echo "  $(printf '%.0s─' {1..40})"

    for ext in mbstring json pcre tokenizer; do
        if php -r "exit(extension_loaded('${ext}') ? 0 : 1);" 2>/dev/null; then
            ok "${ext}"
        else
            fail "${ext} — required but not loaded"; all_ok=false
        fi
    done

    echo ""
    echo "$(printf '%.0s─' {1..50})"
    if [[ "$all_ok" == true ]]; then
        echo -e "  ${GREEN}${BOLD}All requirements met. WPMA is ready.${NC}"
        echo ""
        info "Run a scan:  bash wpma.sh scan /path/to/wordpress"
    else
        echo -e "  ${RED}${BOLD}Some requirements are missing. Fix the issues above.${NC}"
        exit 1
    fi
    echo ""
}

# =============================================================================
# SCAN COMMAND
# =============================================================================
cmd_scan() {
    trap cleanup_scan_runtime EXIT
    trap 'cleanup_scan_runtime; exit 130' INT
    trap 'cleanup_scan_runtime; exit 143' TERM
    local target=""
    local extra_args=()
    local explicit_scope_override=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h)
                show_help
                exit 0
                ;;
            --json)
                extra_args+=(--output json)
                ;;
            --no-color|--progress|--quiet|--quick|--full|--no-core|--no-uploads|--full-site|--core|--plugins|--themes|--file)
                extra_args+=("$1")
                [[ "$1" == "--full-site" || "$1" == "--core" || "$1" == "--plugins" || "$1" == "--themes" || "$1" == "--file" ]] && explicit_scope_override=true
                ;;
            --output|--output-file|--severity|--workers|--max-file-size|--rules-dir|--file-list|--suspicious-list)
                extra_args+=("$1")
                shift
                if [[ $# -eq 0 ]]; then
                    echo -e "${RED}Error: missing value for option ${extra_args[-1]}${NC}" >&2
                    exit 2
                fi
                extra_args+=("$1")
                ;;
            --*)
                extra_args+=("$1")
                ;;
            *)
                if [[ -z "$target" ]]; then
                    target="$1"
                else
                    extra_args+=("$1")
                fi
                ;;
        esac
        shift
    done

    [[ -z "$target" ]] && target="."

    target="$(resolve_target_path "$target")"

    # Verify target exists
    if [[ ! -e "$target" ]]; then
        echo -e "${RED}Error: target does not exist: ${target}${NC}" >&2
        exit 2
    fi

    [[ -d "$target" ]] && target="${target%/}"

    # Detect Windows/Git Bash environment
    local on_windows=false
    if [[ "$(uname -s)" == MINGW* ]] || [[ "$(uname -s)" == CYGWIN* ]] || [[ "$(uname -s)" == MSYS* ]]; then
        on_windows=true
    fi

    # Convert Git Bash path (/c/Users/...) to Windows path (C:/Users/...) for PHP
    php_target="$target"
    if [[ "$on_windows" == true ]] && [[ "$target" =~ ^/([a-zA-Z])/ ]]; then
        php_target="${BASH_REMATCH[1]^^}:${target:2}"
    fi

    # ── Progress flag ──────────────────────────────────────────────────
    local show_progress=false
    local show_wrapper_progress=true
    local quiet_mode=false
    local interactive_output=false
    for arg in "${extra_args[@]:-}"; do
        [[ "${arg:-}" == "--progress" ]] && show_progress=true
        [[ "${arg:-}" == "--quiet" ]] && quiet_mode=true
    done

    [[ -t 1 ]] && interactive_output=true

    if [[ "$quiet_mode" == true ]]; then
        show_progress=false
        show_wrapper_progress=false
    else
        [[ "$interactive_output" == true ]] && show_progress=true
    fi

    if [[ " ${extra_args[*]} " == *" --no-color "* ]]; then
        RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; NC=''
    fi

    # For explicit target overrides, let PHP validate and print first so
    # invalid targets fail before any wrapper-side discovery/progress output.
    [[ "$explicit_scope_override" == true ]] && show_wrapper_progress=false

    # ── Detect scan scope ─────────────────────────────────────────────
    # Used to show the right time-estimate hint before any work starts.
    local scan_scope="unknown"
    local quick_mode=false
    local check_core=true
    for arg in "${extra_args[@]:-}"; do
        [[ "${arg:-}" == "--quick" ]] && quick_mode=true
        [[ "${arg:-}" == "--no-core" ]] && check_core=false
    done

    if [[ " ${extra_args[*]} " == *" --full-site "* ]]; then
        scan_scope="site"
    elif [[ " ${extra_args[*]} " == *" --plugins "* ]]; then
        scan_scope="plugins-dir"
    elif [[ " ${extra_args[*]} " == *" --themes "* ]]; then
        scan_scope="themes-dir"
    elif [[ " ${extra_args[*]} " == *" --file "* ]]; then
        scan_scope="file"
    elif [[ " ${extra_args[*]} " == *" --core "* ]]; then
        scan_scope="core"
    elif [[ -f "$target" ]];                                        then scan_scope="file"
    elif [[ -f "$target/wp-config.php" ]];                          then scan_scope="site"
    elif [[ "$target" =~ /wp-content/plugins/[^/]+$ ]];             then scan_scope="plugin"
    elif [[ "$target" =~ /wp-content/plugins$ ]];                   then scan_scope="plugins-dir"
    elif [[ "$target" =~ /wp-content/themes/[^/]+$ ]];              then scan_scope="theme"
    elif [[ "$target" =~ /wp-content/themes$ ]];                    then scan_scope="themes-dir"
    elif [[ "$target" =~ /wp-content/uploads(/|$) ]];               then scan_scope="uploads"
    elif [[ -d "$target" ]];                                        then scan_scope="directory"
    fi

    # ── Scan header ──────────────────────────────────────────────────
    if [[ "$show_progress" == true ]] && [[ "$show_wrapper_progress" == true ]]; then
        echo -e "" >&2
        echo -e "  ${BOLD}WPMA${NC}  ${CYAN}${target}${NC}" >&2
        echo -e "  $(printf '%0.s─' {1..52})" >&2

        # Contextual time hint — only shown when the scope is large or unknown
        if   [[ "$scan_scope" == "site" ]] && [[ "$quick_mode" == false ]]; then
            echo -e "  ${YELLOW}Full WordPress site scan — this may take several minutes.${NC}" >&2
            echo -e "  Tip: add ${BOLD}--quick${NC} for a fast integrity-only check (under 30 s)." >&2
        elif [[ "$scan_scope" == "plugins-dir" ]]; then
            echo -e "  Scanning installed plugins." >&2
            echo -e "  Tip: add ${BOLD}--quick${NC} to check checksums only." >&2
        elif [[ "$scan_scope" == "plugin" ]]; then
            echo -e "  Single plugin scan." >&2
        elif [[ "$scan_scope" == "themes-dir" ]]; then
            echo -e "  Scanning installed themes." >&2
        elif [[ "$scan_scope" == "theme" ]]; then
            echo -e "  Single theme scan." >&2
        elif [[ "$scan_scope" == "uploads" ]]; then
            echo -e "  Uploads directory scan." >&2
        elif [[ "$scan_scope" == "file" ]]; then
            echo -e "  Single file scan." >&2
        elif [[ "$scan_scope" == "core" ]]; then
            echo -e "  WordPress core scan." >&2
        elif [[ "$scan_scope" == "directory" ]]; then
            echo -e "  Directory malware scan." >&2
        elif [[ "$scan_scope" == "unknown" ]] && [[ "$quick_mode" == false ]]; then
            echo -e "  Directory malware scan." >&2
        fi

        echo -e "" >&2
    fi

    if [[ "$show_progress" == true ]] && [[ "$show_wrapper_progress" == true ]]; then
        shell_activity_start "Preparing scan" "$interactive_output"
    fi

    # ── Shell-side fast path ──────────────────────────────────────────────────
    local file_list_path=""
    local suspicious_list_path=""
    local use_shell_fast_path=false

    if command -v find &>/dev/null && command -v grep &>/dev/null; then
        use_shell_fast_path=true
    fi

    # Explicit scope overrides may change the effective scan path in PHP, so
    # disable the shell fast-path and let the PHP resolver own discovery.
    if [[ "$explicit_scope_override" == true ]]; then
        use_shell_fast_path=false
    fi

    if [[ "$use_shell_fast_path" == true ]]; then
        local plan_total
        plan_total="$(scan_plan_total "$scan_scope" "$quick_mode" "$check_core")"

        # Detect Windows/Git Bash
        local on_windows=false
        if [[ "$(uname -s)" == MINGW* ]] || [[ "$(uname -s)" == CYGWIN* ]] || [[ "$(uname -s)" == MSYS* ]]; then
            on_windows=true
        fi

        # Build exclude prune expressions
        local prune_args=()
        for dir in "${EXCLUDE_DIRS[@]}"; do
            prune_args+=('-o' '-name' "$dir" '-prune')
        done

        local all_files_tmp suspicious_tmp
        all_files_tmp=$(mktemp "${TMPDIR:-/tmp}/wpma_all_XXXXXX.txt")
        suspicious_tmp=$(mktemp "${TMPDIR:-/tmp}/wpma_sus_XXXXXX.txt")
        WPMA_SCAN_ALL_TMP="$all_files_tmp"
        WPMA_SCAN_SUSPICIOUS_TMP="$suspicious_tmp"

        # Note on the two-list design:
        #   --file-list      = ALL PHP files found by find (used for plugin integrity detection)
        #   --suspicious-list = grep-filtered subset (used to skip deep scan on clean files)
        # Separating them ensures plugins with zero suspicious PHP files still get
        # integrity-checked (extra files like extensionless archives are caught).

        # ── Step 1: find ───────────────────────────────────────────────────────
        shell_activity_stop
        if [[ "$show_progress" == true ]] && [[ "$show_wrapper_progress" == true ]]; then
            shell_activity_start "Indexing PHP files..." "$interactive_output"
        fi

        find "$target" \
            \( -false "${prune_args[@]}" \) -prune \
            -o \( "${FIND_EXTS[@]}" \) -readable -print \
            2>/dev/null | awk -v on_win="$on_windows" -v status_file="$WPMA_ACTIVITY_STATUS_FILE" '
            {
                # Convert Git Bash path to Windows path if needed
                if (on_win && $0 ~ /^\/[a-zA-Z]\//) {
                    drive = toupper(substr($0, 2, 1))
                    rest  = substr($0, 3)
                    line  = drive ":" rest
                } else {
                    line = $0
                }
                print line
                count++
                if (status_file != "" && (count == 1 || count % 100 == 0)) {
                    printf "Indexing PHP files... %d indexed", count > status_file
                    close(status_file)
                }
            }
        ' > "$all_files_tmp"

        shell_activity_stop

        local total_found
        local visible_plan_total
        total_found=$(wc -l < "$all_files_tmp" | tr -d ' ')
        visible_plan_total="$plan_total"

        if [[ "$total_found" -eq 0 ]]; then
            visible_plan_total=$((visible_plan_total - 1))
        fi

        if [[ "$show_progress" == true ]] && [[ "$show_wrapper_progress" == true ]]; then
            echo -e "  ${CYAN}1/${visible_plan_total}${NC}  Indexing PHP files..." >&2
            if [[ "$total_found" -gt 1000 ]]; then
                printf "  ${GREEN}\u2714${NC}    %d PHP files  ${YELLOW}(smart mode will skip clean components)${NC}\n" \
                    "$total_found" >&2
            else
                printf "  ${GREEN}\u2714${NC}    %d PHP files\n" "$total_found" >&2
            fi
        fi

        # ── Step 2: grep ──────────────────────────────────────────────────────
        local suspicious_count=0

        if [[ "$total_found" -gt 0 ]]; then
            local grep_args=()
            for pattern in "${GREP_PATTERNS[@]}"; do
                grep_args+=('-e' "$pattern")
            done

            if [[ "$show_progress" == true ]] && [[ "$show_wrapper_progress" == true ]]; then
                shell_activity_start "Pattern filtering..." "$interactive_output"
            fi

            xargs grep -lEi "${grep_args[@]}" \
                < "$all_files_tmp" \
                2>/dev/null > "$suspicious_tmp" || true

            shell_activity_stop

            if [[ "$show_progress" == true ]] && [[ "$show_wrapper_progress" == true ]]; then
                echo -e "  ${CYAN}2/${visible_plan_total}${NC}  Pattern filtering..." >&2
            fi

            suspicious_count=$(wc -l < "$suspicious_tmp" | tr -d ' ')

            if [[ "$show_progress" == true ]] && [[ "$show_wrapper_progress" == true ]]; then
                printf "  ${GREEN}\u2714${NC}    %d suspicious candidate(s) identified from %d PHP file(s)\n" \
                    "$suspicious_count" "$total_found" >&2
            fi
        else
            touch "$suspicious_tmp"
            if [[ "$show_progress" == true ]] && [[ "$show_wrapper_progress" == true ]]; then
                echo -e "  ${YELLOW}\u26a0${NC}    No PHP files found in target" >&2
            fi
        fi

        # Pass the FULL file list for plugin detection, plus the grep-filtered
        # suspicious list so PHP can skip the deep scan on clean files.
        file_list_path="$all_files_tmp"
        suspicious_list_path="$suspicious_tmp"

    else
        shell_activity_stop
        if [[ "$show_progress" == true ]] && [[ "$show_wrapper_progress" == true ]]; then
            echo -e "  ${YELLOW}\u26a0${NC}    find/grep not available — PHP will handle file discovery" >&2
        fi
    fi

    # ── Build PHP command ─────────────────────────────────────────────────────
    local php_args=("${PHP_ENTRY}" scan "$php_target")

    # Pass both file lists to PHP when the shell fast-path ran
    if [[ -n "${file_list_path:-}" ]]; then
        php_args+=('--file-list' "$file_list_path")
    fi
    if [[ -n "${suspicious_list_path:-}" ]]; then
        php_args+=('--suspicious-list' "$suspicious_list_path")
    fi

    # Forward remaining user args
    php_args+=("${extra_args[@]:-}")

    # Add --progress if terminal and not already present
    if [[ "$show_progress" == true ]]; then
        local already_has_progress=false
        for arg in "${extra_args[@]:-}"; do
            [[ "${arg:-}" == "--progress" ]] && already_has_progress=true
        done
        [[ "$already_has_progress" == false ]] && php_args+=('--progress')
    fi

    # Run PHP scanner
    shell_activity_stop
    exec php "${php_args[@]}"
}

# =============================================================================
# MAIN
# =============================================================================
show_help() {
    echo -e "${BOLD}WPMA v2 — WordPress Malware Analysis Toolkit${NC}"
    echo ""
    echo -e "  ${BOLD}Usage:${NC}"
    echo "    bash wpma.sh help                      Show this help message"
    echo "    bash wpma.sh check                     Check environment requirements"
    echo "    bash wpma.sh scan [path] [options]     Scan a WordPress site, component, file, or directory"
    echo "    bash wpma.sh version                   Show version"
    echo ""
    echo -e "  ${BOLD}Commands:${NC}"
    echo "    help              Display available commands and options"
    echo "    check             Verify required tools and PHP availability"
    echo "    scan              Run a malware and integrity scan"
    echo "    version           Print the current WPMA version"
    echo ""
    echo -e "  ${BOLD}Target selection:${NC}"
    echo "    [path]            Optional; defaults to the current directory"
    echo "    --full-site       Force full WordPress site detection"
    echo "    --core            Force WordPress core target detection"
    echo "    --plugins         Force wp-content/plugins detection"
    echo "    --themes          Force wp-content/themes detection"
    echo "    --file            Force single-file detection"
    echo ""
    echo -e "  ${BOLD}Scan modes:${NC}"
    echo "    (default)          Smart: integrity first, deep scan only if issues found"
    echo "    --quick            Integrity check only — fastest, no malware pattern scan"
    echo "    --full             Force deep scan everything (ignore verified-skip)"
    echo ""
    echo -e "  ${BOLD}Scope flags:${NC}"
    echo "    --no-core          Skip WordPress core checksum check"
    echo "    --no-uploads       Skip uploads directory anomaly scan"
    echo ""
    echo -e "  ${BOLD}Output flags:${NC}"
    echo "    --output [text|json]                   Output format (default: text)"
    echo "    --json                                 Shortcut for --output json"
    echo "    --output-file <path>                   Write report to file"
    echo "    --severity [info|low|medium|high|critical]"
    echo "    --no-color                             Disable ANSI colors"
    echo "    --progress                             Show detailed per-step progress"
    echo "    --quiet                                Suppress progress/status output"
    echo ""
    echo -e "  ${BOLD}Examples:${NC}"
    echo "    bash wpma.sh scan /var/www/html                   Full smart scan"
    echo "    bash wpma.sh scan --plugins /var/www/html         Scan all plugins in a site"
    echo "    bash wpma.sh scan /var/www/html --quick           Integrity only (fast)"
    echo "    bash wpma.sh scan /var/www/html --full            Force scan everything"
    echo "    bash wpma.sh scan wp-content/plugins/my-plugin    Single plugin scan"
    echo "    bash wpma.sh scan /var/www/html --no-core         Skip core check"
    echo ""
}

if [[ $# -eq 0 ]]; then
    show_help
    exit 0
fi

COMMAND="${1}"
shift

case "$COMMAND" in
    help|-h|--help) show_help ;;
    check)          cmd_check ;;
    scan)           cmd_scan "$@" ;;
    version)        exec php "${PHP_ENTRY}" version ;;
    *)              echo -e "${RED}Unknown command: ${COMMAND}${NC}"; echo "Run 'bash wpma.sh help' for usage."; exit 2 ;;
esac
