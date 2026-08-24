#!/usr/bin/env bash
#
# check-public-safety.sh — public-repository leak gate for Tracexy.
#
# Purpose
#   Audit everything a public clone could ship for private material that must
#   never leave the private working tree: machine-specific paths, personal
#   contact addresses, real credentials, the Apple Team ID, sibling-product
#   (Rockxy) internals, monetization/licensing strategy, and private-only
#   activation/licensing source files.
#
#   Scope is TWO surfaces, because a first push publishes both:
#     1. The current shippable tree — tracked files + untracked files that are
#        NOT gitignored.
#     2. Reachable Git history — every commit/blob reachable from the current
#        branch HEAD. Redacted, personal, or secret material in old commits ships
#        with that branch even if the current tree is spotless. Unrelated local
#        branches are intentionally out of scope for a single-branch push.
#
#   This replaces the old, gitignored `scripts/check-leaks.sh` so a fresh public
#   clone is self-contained: the CI gate lives inside `.github/`, which ships.
#
# Contract
#   - Read-only. No writes, no temp files, no network, no mutations, no secrets.
#     History checks use only read-only plumbing (`git log`, `git rev-list`,
#     `git grep <rev>...`); they never rewrite or mutate anything.
#   - Enumerates current candidates with
#     `git ls-files --cached --others --exclude-standard` so `.gitignore` decides
#     scope for the tree surface (this file must not loosen `.gitignore`).
#   - Portable to macOS's system Bash 3.2: no associative arrays, no `mapfile`,
#     no `${var^^}`, no process substitution, no GNU-only flags, no temp files.
#   - Exit codes: 0 = clean, 1 = findings, 2 = bad usage / setup error.
#   - Findings print LOCATION ONLY — `file:line` (tree) or `commit`/`object` +
#     `path`/`line` (history) plus a category. The matched source content, the
#     personal address, the secret value, and the concrete Team ID are NEVER
#     printed, so the gate's own output can never become the leak.
#
# Self-exclusion (principled and explicit)
#   This script necessarily *contains* every forbidden signature it hunts for
#   (the regexes below literally spell out PEM headers, key prefixes, the Rockxy
#   token, licensing phrases, etc.). Scanning it against its own content rules
#   would guarantee false positives, so this file is excluded from the CONTENT
#   checks by path. Its *existence, path, and shell syntax* remain fully visible
#   to code review and to CI/Codex (they run and read it), so nothing is hidden:
#   only the pattern source is exempted from matching itself.

set -u

usage() {
    cat <<'USAGE'
Usage: bash .github/scripts/check-public-safety.sh

Scans all Git-shippable files (tracked + non-ignored untracked) for private
material. Run from anywhere inside the repository. Takes no arguments.

Exit status: 0 clean, 1 findings, 2 bad usage or setup error.
USAGE
}

# --- Argument handling -------------------------------------------------------
case "${1:-}" in
    "") : ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        printf 'error: unexpected argument: %s\n\n' "$1" >&2
        usage >&2
        exit 2
        ;;
esac

# --- Setup / preconditions (exit 2 on failure) -------------------------------
command -v git >/dev/null 2>&1 || {
    printf 'error: git is required but was not found on PATH.\n' >&2
    exit 2
}

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    printf 'error: not inside a Git repository.\n' >&2
    exit 2
}

cd "$REPO_ROOT" 2>/dev/null || {
    printf 'error: cannot enter repository root: %s\n' "$REPO_ROOT" >&2
    exit 2
}

# This script's own repo-relative path — excluded from content scanning.
# Self-exclusion is restricted to this EXACT canonical path: a differently
# located file that merely shares the basename (e.g. nested/check-public-safety.sh)
# is NOT exempt and is content-scanned like any other candidate.
SELF_PATH=".github/scripts/check-public-safety.sh"

# --- Forbidden path policy (evaluated before any binary/content skip) --------
# Some material must FAIL on its path alone — never silently skipped as "binary"
# and never trusted to be absent just because `.gitignore` would hide it (a
# *tracked* file ships regardless of ignore rules). Returns a human-readable
# reason on stdout for a forbidden path, or nothing for an allowed one.
forbidden_reason() {
    fp="$1"
    flc="$(printf '%s' "$fp" | tr '[:upper:]' '[:lower:]')"
    fblc="${flc##*/}"

    # Agent / tool metadata that can leak local instructions or configuration.
    # Matched case-insensitively; canonical product source is unaffected because
    # these names/dirs are distinctive. Directories appear as path components.
    case "$flc" in
    claude.md | */claude.md \
        | agents.md | */agents.md \
        | gemini.md | */gemini.md \
        | .cursorrules | */.cursorrules \
        | .mcp.json | */.mcp.json \
        | .claude/* | */.claude/* \
        | .codex/* | */.codex/* \
        | .agents/* | */.agents/* \
        | .cursor/* | */.cursor/*)
        printf 'agent/tool metadata (may leak local instructions or config)'
        return 0
        ;;
    esac

    # Environment files — allow only committed example/template/sample stubs.
    # First-match-wins ordering keeps the stubs allowed before the catch-all.
    case "$fblc" in
    .env.example | .env.template | .env.sample \
        | .env.*.example | .env.*.template | .env.*.sample)
        : ;;
    .env | .env.*)
        printf 'environment file (may contain secrets)'
        return 0
        ;;
    esac

    # Credentials file.
    case "$fblc" in
    .netrc | netrc)
        printf 'credentials file (.netrc)'
        return 0
        ;;
    esac

    # Private keys and certificates — never publishable.
    case "$flc" in
    *.key | *.p8 | *.p12 | *.pem | *.cer | *.der \
        | *.keychain | *.keychain-db | *.mobileprovision)
        printf 'private key or certificate material'
        return 0
        ;;
    esac

    # Packet captures / session exports — real traffic must never ship.
    case "$flc" in
    *.pcap | *.pcapng | *.pcap.* | *.pcapng.*)
        printf 'packet capture export'
        return 0
        ;;
    esac

    return 0
}

# --- Build the candidate file list ------------------------------------------
# Everything Git could include: tracked (--cached) plus untracked-but-not-ignored
# (--others --exclude-standard). `.gitignore` is honored, so build artifacts,
# Developer.xcconfig, *.pem, scripts/, .claude/, etc. are already out of scope.
FILES=()
FORBIDDEN_OUT=""
while IFS= read -r path; do
    [ -n "$path" ] || continue
    [ -f "$path" ] || continue

    # Self-exclusion from content rules (see header) — EXACT canonical path only.
    [ "$path" = "$SELF_PATH" ] && continue

    # Path-level policy runs BEFORE any binary/content skip so sensitive
    # key/cert/capture/metadata files can never be silently skipped.
    reason="$(forbidden_reason "$path")"
    if [ -n "$reason" ]; then
        FORBIDDEN_OUT="${FORBIDDEN_OUT}${path}:1: forbidden sensitive path — ${reason}
"
        continue
    fi

    # Skip obvious binary / image / vendor noise only. Everything else —
    # including Markdown and .pbxproj — is scanned. grep -I is a second safety
    # net for any binary that slips past these extensions.
    lc="$(printf '%s' "$path" | tr '[:upper:]' '[:lower:]')"
    case "$lc" in
        */node_modules/* | */pods/* | */carthage/* | */.build/* | */build/* | */vendor/* | */third_party/*)
            continue
            ;;
        *.png | *.jpg | *.jpeg | *.gif | *.bmp | *.ico | *.icns | *.tif | *.tiff | *.webp | *.svg)
            continue
            ;;
        *.pdf | *.zip | *.gz | *.tgz | *.tar | *.dmg | *.bin | *.dat)
            continue
            ;;
        *.p12 | *.pem | *.cer | *.der | *.p8 | *.mobileprovision | *.keychain)
            continue
            ;;
        *.woff | *.woff2 | *.ttf | *.otf | *.eot)
            continue
            ;;
        *.mp4 | *.mov | *.m4v | *.mp3 | *.wav | *.aiff)
            continue
            ;;
        *.jar | *.class | *.so | *.dylib | *.a | *.o)
            continue
            ;;
        *.pcap | *.pcapng | *.xcuserstate)
            continue
            ;;
    esac

    FILES+=("$path")
done <<EOF
$(git ls-files --cached --others --exclude-standard 2>/dev/null)
EOF

# --- Finding accounting ------------------------------------------------------
FINDINGS=0

# report LABEL CONTENT
# CONTENT is `file:line:content` lines captured from grep/awk. Prints them under
# a category header and adds their count to the global finding total. Content is
# passed as an argument (not piped) so the FINDINGS increment runs in THIS shell
# — piping into a function would run it in a subshell and silently drop the count.
report() {
    label="$1"
    out="$2"
    [ -n "$out" ] || return 0
    printf '\n[FAIL] %s\n' "$label"
    printf '%s\n' "$out" | while IFS= read -r line; do
        printf '  %s\n' "$line"
    done
    n="$(printf '%s\n' "$out" | grep -c .)"
    FINDINGS=$((FINDINGS + n))
}

# emit_locations LABEL RAW NFIELDS
# RAW holds grep / git-grep output ("a:b:c:...content"). Keep ONLY the first
# NFIELDS colon-separated fields — the location (file:line for the tree,
# commit:path:line for history) — and DROP everything after. The matched source
# content and any secret value are therefore never printed; only the location
# and (via LABEL) the category are shown. Deduplicate locations, print them under
# the category header, and add the unique count to the global finding total.
# Content is passed as an argument (not piped) so the FINDINGS increment runs in
# THIS shell, exactly like report().
emit_locations() {
    el_label="$1"
    el_raw="$2"
    el_fields="$3"
    [ -n "$el_raw" ] || return 0
    el_loc="$(printf '%s\n' "$el_raw" | cut -d: -f1-"$el_fields" | grep -v '^$' | sort -u)"
    [ -n "$el_loc" ] || return 0
    printf '\n[FAIL] %s\n' "$el_label"
    printf '%s\n' "$el_loc" | while IFS= read -r line; do
        printf '  %s\n' "$line"
    done
    el_n="$(printf '%s\n' "$el_loc" | grep -c .)"
    FINDINGS=$((FINDINGS + el_n))
}

# Path-level policy findings first — these fail on identity alone, so they must
# be counted even if no file survives to the content scan below.
report "Forbidden sensitive path (policy)" "$FORBIDDEN_OUT"

# --- Reachable-history checks (run regardless of the current-tree candidates) -
# A first push publishes every reachable object, not just the working tree, so
# these read-only checks scan branch/tag history. They emit LOCATION ONLY: never
# the offending address, the secret, or the Team ID itself.

# H1: personal webmail in commit author/committer metadata. The email is fed into
# grep but never emitted — only the commit hash is printed. `%x09` is a tab, so
# `cut -f1` (default tab delimiter) extracts the hash and discards the addresses.
#
# The exact hashes below are merge commits that were already public before this
# forward-looking gate could enforce noreply metadata. Rewriting published tags
# would be more harmful than retaining them, so only those immutable objects are
# baselined; every new commit remains subject to the strict check.
legacy_personal_mail_commit() {
    case "$1" in
    09d3dd91c755fd853e79b5d49762140263149993 \
        | 523b17b715a890f566b3f8e958625d7482113127 \
        | 5f0ec0b18c4193263a918f85de1e41257f9d8f6d \
        | 7abcb836c52cb4f29c9518e711bcde3bafff9711 \
        | a3752dea56349fcf5393c1451d8fab58e8da1e03 \
        | ab8987c7c67cb1209c9f12b0083f11f9dcb8779f \
        | ae8849cf6e5b7f3ab634d8619a112248ab0102eb \
        | de25765496efc9da0a07cfce5fca9605ca908367 \
        | e0b62af78a5378159f0a9b9400ecd0456340122e \
        | e790c089cf4aa7a8f4f2d6054e489f4443a6494e)
        return 0
        ;;
    *)
        return 1
        ;;
    esac
}

hist_mail_hashes="$(git log HEAD --format='%H%x09%ae%x09%ce' 2>/dev/null \
    | grep -iE '@(gmail|googlemail|yahoo|ymail|hotmail|outlook|live|msn|icloud|me|mac|aol|gmx|proton|protonmail|pm|zoho|fastmail)\.[A-Za-z]{2,}' \
    | cut -f1 | sort -u)"
hist_mail_out=""
if [ -n "$hist_mail_hashes" ]; then
    hist_mail_out="$(printf '%s\n' "$hist_mail_hashes" | while IFS= read -r h; do
        [ -n "$h" ] || continue
        legacy_personal_mail_commit "$h" && continue
        printf '%s: personal webmail in commit author/committer metadata\n' "$h"
    done)"
fi
report "Personal webmail in commit metadata (history)" "$hist_mail_out"

# H2: agent/tool metadata paths ever committed (path only, case-insensitive).
# `git rev-list --all --objects` prints "<object-sha> <path>"; commit/tree lines
# without a trailing path never match the name-anchored pattern. Directory names
# are anchored by a leading space or slash and a trailing slash or end-of-line;
# file names are anchored by a leading space or slash and end-of-line.
hist_meta="$(git rev-list HEAD --objects 2>/dev/null \
    | grep -iE '([ /])(\.claude|\.codex|\.agents|\.cursor)([/]|$)|([ /])(claude\.md|agents\.md|gemini\.md|\.cursorrules|\.mcp\.json)$' \
    | sort -u)"
hist_meta_out=""
if [ -n "$hist_meta" ]; then
    hist_meta_out="$(printf '%s\n' "$hist_meta" | while IFS= read -r line; do
        [ -n "$line" ] || continue
        obj="${line%% *}"
        pth="${line#* }"
        printf '%s  (object %s): agent/tool metadata path committed to history\n' "$pth" "$obj"
    done)"
fi
report "Agent/tool metadata path committed in history" "$hist_meta_out"

# H3 / H4: secret material and concrete Apple Team IDs in reachable commit
# content. `git grep <rev>...` searches each reachable revision's tree and prints
# "commit:path:line:content". SELF_PATH is filtered out (field 2) to preserve
# self-exclusion; output is cut to commit:path:line (content never printed) and
# deduplicated per location (`sort -t: -k2 -u` collapses the same path:line that
# rides unchanged across many commits down to one representative commit).
HIST_REVS="$(git rev-list HEAD 2>/dev/null)"
if [ -n "$HIST_REVS" ]; then
    hist_secret="$(git grep -I -n -E \
        -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' \
        -e 'AKIA[0-9A-Z]{16}' \
        -e 'ASIA[0-9A-Z]{16}' \
        -e 'gh[posru]_[A-Za-z0-9]{20,}' \
        -e 'github_pat_[A-Za-z0-9_]{20,}' \
        -e 'xox[baprs]-[A-Za-z0-9-]{10,}' \
        -e 'AIza[0-9A-Za-z_-]{35}' \
        -e '(sk|rk)_live_[0-9A-Za-z]{16,}' \
        -e 'sk-[A-Za-z0-9_-]{32,}' \
        -e 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' \
        $HIST_REVS 2>/dev/null \
        | awk -F: -v self="$SELF_PATH" '$2 != self' \
        | cut -d: -f1-3 | sort -t: -k2 -u)"
    emit_locations "Concrete credential or private-key material (history)" "$hist_secret" 3

    hist_team="$(git grep -I -n -E \
        -e 'DEVELOPMENT_TEAM[[:space:]]*=[[:space:]]*"?[A-Z0-9]{10}"?' \
        -e '[Tt]eam[ _]?ID[^A-Za-z0-9]{0,4}[A-Z0-9]{10}' \
        -e '[Aa]pple team[^A-Za-z0-9]{0,4}[A-Z0-9]{10}' \
        $HIST_REVS 2>/dev/null \
        | awk -F: -v self="$SELF_PATH" '$2 != self' \
        | cut -d: -f1-3 | sort -t: -k2 -u)"
    emit_locations "Concrete Apple Team ID (history)" "$hist_team" 3
fi

# Only a genuinely empty tree (no candidates AND no policy findings) is a setup
# error. If policy findings exist, fall through to the verdict and exit 1.
if [ "${#FILES[@]}" -eq 0 ]; then
    if [ "$FINDINGS" -eq 0 ]; then
        printf 'error: no scannable files found (unexpected).\n' >&2
        exit 2
    fi
    printf '\n'
    printf 'check-public-safety: %d finding(s). Resolve or redact before publishing.\n' "$FINDINGS" >&2
    exit 1
fi

# --- Check 1: absolute machine paths under /Users or /Volumes ----------------
c_out="$(grep -nHIE '/(Users|Volumes)/[A-Za-z0-9._-]+' "${FILES[@]}" 2>/dev/null)"
emit_locations "Absolute machine path (/Users or /Volumes)" "$c_out" 2

# --- Check 2: personal webmail addresses -------------------------------------
c_out="$(grep -nHIiE '[A-Za-z0-9._%+-]+@(gmail|googlemail|yahoo|ymail|hotmail|outlook|live|msn|icloud|me|mac|aol|gmx|proton|protonmail|pm|zoho|fastmail)\.[A-Za-z]{2,}' "${FILES[@]}" 2>/dev/null)"
emit_locations "Personal webmail address" "$c_out" 2

# --- Check 3: concrete credential / private-key material ---------------------
# Prefix- and PEM-anchored so bare variable names (API_KEY, password, token=...)
# do NOT match — only material that is unmistakably a real secret.
c_out="$(grep -nHIE -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' \
    -e 'AKIA[0-9A-Z]{16}' \
    -e 'ASIA[0-9A-Z]{16}' \
    -e 'gh[posru]_[A-Za-z0-9]{20,}' \
    -e 'github_pat_[A-Za-z0-9_]{20,}' \
    -e 'xox[baprs]-[A-Za-z0-9-]{10,}' \
    -e 'AIza[0-9A-Za-z_-]{35}' \
    -e '(sk|rk)_live_[0-9A-Za-z]{16,}' \
    -e 'sk-[A-Za-z0-9_-]{32,}' \
    -e 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' \
    "${FILES[@]}" 2>/dev/null)"
emit_locations "Concrete credential or private-key material" "$c_out" 2

# --- Check 4: concrete Apple Team ID -----------------------------------------
# A Team ID is 10 uppercase alphanumerics. Require a signing/labeling context so
# unrelated 10-char tokens do not match, and so an EMPTY assignment
# (DEVELOPMENT_TEAM = ) — as CI writes — is never flagged.
c_out="$(grep -nHIE -e 'DEVELOPMENT_TEAM[[:space:]]*=[[:space:]]*"?[A-Z0-9]{10}"?' \
    -e '[Tt]eam[ _]?ID[^A-Za-z0-9]{0,4}[A-Z0-9]{10}' \
    -e '[Aa]pple team[^A-Za-z0-9]{0,4}[A-Z0-9]{10}' \
    "${FILES[@]}" 2>/dev/null)"
emit_locations "Concrete Apple Team ID" "$c_out" 2

# --- Check 5: sibling-product token 'rockxy' -------------------------------
# Strip the canonical public source path and Tracexy website route from a copy
# of each line;
# if 'rockxy' still survives (case-insensitively) the line leaks sibling-product
# naming. awk prints the ORIGINAL line; the strip is only for the decision.
c_out="$(grep -nHIi 'rockxy' "${FILES[@]}" 2>/dev/null \
    | awk '{ t = $0; gsub(/RockxyApp\/Tracexy/, "", t); gsub(/https:\/\/rockxy\.io\/tracexy/, "", t); if (tolower(t) ~ /rockxy/) print $0 }')"
emit_locations "Sibling-product token 'rockxy' (canonical Tracexy routes allowed)" "$c_out" 2

# --- Check 6: monetization / licensing strategy phrases ----------------------
c_out="$(grep -nHIiE -e 'pricing' \
    -e 'monetiz(e|ing|ation)' \
    -e 'monetis(e|ing|ation)' \
    -e '(entitlement|licen[sc]e|activation) key' \
    -e 'paid (tier|plan)' \
    -e 'per[- ]seat' \
    -e 'founding (member|plan|user|tier)' \
    -e 'founder (plan|tier)' \
    "${FILES[@]}" 2>/dev/null)"
emit_locations "Monetization / licensing strategy phrase" "$c_out" 2

# --- Check 7: private-only activation / licensing source basenames -----------
# These types live behind the private AppPolicy boundary (the public tree ships
# only AppPolicy / DefaultAppPolicy / AppPolicyProvider). Their presence — or
# any reference to them — signals a private file leaking into the public repo.
PRIVATE_BASENAMES="Activation.swift ActivationService.swift ActivationStore.swift ActivationTests.swift ActivationViewModel.swift FullAccessAppPolicy.swift KeychainStore.swift LicenseRuntimeConfiguration.swift LicenseServiceTests.swift LicenseSettingsView.swift LicenseSignatureVerifier.swift MachineIdentity.swift RockxyBELicenseService.swift"

# 7a: any candidate file that IS one of these private basenames.
present_out=""
for f in "${FILES[@]}"; do
    base="${f##*/}"
    for priv in $PRIVATE_BASENAMES; do
        if [ "$base" = "$priv" ]; then
            present_out="${present_out}${f}:1: private-only file present in public tree
"
        fi
    done
done
report "Private-only activation/licensing file present" "$present_out"

# 7b: references to those basenames inside shipped content (docs, project files).
c_out="$(grep -nHIF \
    -e 'Activation.swift' \
    -e 'ActivationService.swift' \
    -e 'ActivationStore.swift' \
    -e 'ActivationTests.swift' \
    -e 'ActivationViewModel.swift' \
    -e 'FullAccessAppPolicy.swift' \
    -e 'KeychainStore.swift' \
    -e 'LicenseRuntimeConfiguration.swift' \
    -e 'LicenseServiceTests.swift' \
    -e 'LicenseSettingsView.swift' \
    -e 'LicenseSignatureVerifier.swift' \
    -e 'MachineIdentity.swift' \
    -e 'RockxyBELicenseService.swift' \
    "${FILES[@]}" 2>/dev/null)"
emit_locations "Reference to a private-only activation/licensing file" "$c_out" 2

# --- Verdict -----------------------------------------------------------------
printf '\n'
if [ "$FINDINGS" -gt 0 ]; then
    printf 'check-public-safety: %d finding(s). Resolve or redact before publishing.\n' "$FINDINGS" >&2
    exit 1
fi

printf 'check-public-safety: clean — no private material detected.\n'
exit 0
