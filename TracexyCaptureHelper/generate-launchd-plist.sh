#!/bin/bash
set -euo pipefail

# Generates the SMAppService launch-daemon plist embedded in the app bundle at
# Contents/Library/LaunchDaemons, with identity values resolved from the ACTIVE
# build configuration. This is the seam that keeps local-dev and production builds
# from ever sharing a BTM label / Mach service: the filename and every value below
# come from the same TRACEXY_* build settings that drive TracexyIdentity at
# runtime, so the bundled plist always matches TracexyIdentity.current.
#
# Runs as the app target's "Generate LaunchDaemon Plist" shell-script build phase.
# It replaces the old static Copy-Files phase, which could only ship a single
# hardcoded com.amunx.tracexy.helper.plist regardless of configuration.
#
# Lives under the tracked TracexyCaptureHelper/ folder (NOT scripts/, which is
# gitignored maintainer tooling) because the app build depends on it: a fresh
# checkout must be able to build without any local-only files.

: "${TRACEXY_HELPER_MACH_SERVICE_NAME:?missing build setting}"
: "${TRACEXY_HELPER_BUNDLE_PROGRAM:?missing build setting}"
: "${TRACEXY_HELPER_PLIST_NAME:?missing build setting}"
: "${TRACEXY_ALLOWED_CALLER_IDENTIFIERS:?missing build setting}"
: "${CODESIGNING_FOLDER_PATH:?missing build setting}"

dest_dir="$CODESIGNING_FOLDER_PATH/Contents/Library/LaunchDaemons"
dest="$dest_dir/$TRACEXY_HELPER_PLIST_NAME"
mkdir -p "$dest_dir"

{
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    echo '<plist version="1.0">'
    echo '<dict>'
    echo '    <key>Label</key>'
    echo "    <string>${TRACEXY_HELPER_MACH_SERVICE_NAME}</string>"
    echo '    <key>BundleProgram</key>'
    echo "    <string>${TRACEXY_HELPER_BUNDLE_PROGRAM}</string>"
    echo '    <key>MachServices</key>'
    echo '    <dict>'
    echo "        <key>${TRACEXY_HELPER_MACH_SERVICE_NAME}</key>"
    echo '        <true/>'
    echo '    </dict>'
    echo '    <key>AssociatedBundleIdentifiers</key>'
    echo '    <array>'
    for identifier in $TRACEXY_ALLOWED_CALLER_IDENTIFIERS; do
        echo "        <string>${identifier}</string>"
    done
    echo '    </array>'
    echo '</dict>'
    echo '</plist>'
} > "$dest"

plutil -lint "$dest" >/dev/null
echo "Generated launch daemon plist: $dest"
