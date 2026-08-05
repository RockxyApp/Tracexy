# Getting started

## Requirements

- **macOS 14 or later** — the documented baseline.
- **Xcode 16 or later** to build.
- Optional, for contributors: [SwiftLint](https://github.com/realm/SwiftLint) and
  [SwiftFormat](https://github.com/nicklockwood/SwiftFormat). They are the authority on style; you
  don't need them just to build and run.

Opening saved capture files works with no special privileges. **Live capture** additionally requires
a one-time install of the privileged helper (see below).

## Get the source

```bash
git clone https://github.com/RockxyApp/Tracexy.git
cd Tracexy
```

## Signing setup

Builds are code-signed, and the app and its privileged helper validate each other's signatures at
runtime, so you need to point the project at **your own** Apple Developer Team.

```bash
cp Configuration/Developer.xcconfig.template Configuration/Developer.xcconfig
```

Edit `Configuration/Developer.xcconfig` and set `TRACEXY_TEAM_ID` to your 10-character Team ID (find
it at <https://developer.apple.com/account> → Membership Details):

```
TRACEXY_TEAM_ID = YOURTEAMID
CODE_SIGN_IDENTITY = Apple Development
DEVELOPMENT_TEAM = $(TRACEXY_TEAM_ID)
```

`Developer.xcconfig` is gitignored, so your signing identity never enters version control. Never
commit it.

## Build and test

```bash
# Build
xcodebuild -project Tracexy.xcodeproj -scheme Tracexy -destination 'platform=macOS' build

# Test
xcodebuild -project Tracexy.xcodeproj -scheme Tracexy -destination 'platform=macOS' test
```

The project uses Xcode's file-system-synchronized groups: adding a Swift file under `Tracexy/` or
`TracexyTests/` needs no project-file edit — create the file and build.

Contributors should run the linters before submitting:

```bash
swiftformat . && swiftlint lint --strict
```

## Live capture vs. saved captures

- **Saved captures** — open a `.pcap` or `.pcapng` from disk. No helper, no admin rights. This is the
  quickest way to see the full pipeline: the file is read, decoded, and grouped into sessions.
- **Live capture** — captures from a network interface through the signed privileged helper. The
  helper installs as a login item and needs one-time approval (System Settings → Login Items) or an
  admin install; after that, capture runs without `sudo`. By default, live capture starts when you
  press **Start**. If you explicitly enable **Settings → Capture → Auto-start capture on launch**,
  Tracexy starts capture after launch setup completes.

Changes to the helper (`TracexyCaptureHelper/`) or the shared XPC protocol are **not** picked up by
rebuilding the app. You must uninstall the helper, rebuild, and reinstall.

Local development builds run under a **separate, isolated identity** from the shipping app: a Debug
build is `com.amunx.tracexy.dev` with helper `com.amunx.tracexy.dev.helper` (and its own
`com.amunx.tracexy.dev.helper.plist` launch daemon), while shipping Community builds stay
`com.amunx.tracexy.community` / `com.amunx.tracexy.helper`. This is deliberate: it prevents a DerivedData
build from registering under the production helper's launchd/Background-Items label, which otherwise
mixes the two under one label and makes the installed helper unlaunchable. All identity is resolved at
runtime from the built `Info.plist`; nothing is hardcoded in Swift. A dev build therefore keeps its own
Login-Items approval and defaults domain, independent of any installed release.

Next: [Usage](usage.md) · [Architecture](architecture.md)
