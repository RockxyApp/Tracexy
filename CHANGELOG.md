# Changelog

All notable changes to Tracexy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- Protect native session exports with Privacy settings, omitting raw packet bytes and sensitive decoded metadata by default; raw pcap/pcapng exports now require explicit confirmation while a protection is enabled.

### Fixed

- Strengthen privileged capture-helper authentication against process-identity races.
- Remove temporary capture files left by interrupted sessions without touching active captures or unrelated data.

### Changed

## [0.3.0] - 2026-08-17

### Added

- Add a capture summary dashboard with traffic activity, protocol mix, top talkers, and evidence-based findings.
- Add native session search, decoded-evidence copy actions, source management, and reversible session removal.
- Add deeper STUN, TLS-record, and QUIC long-header inspection, plus segmented TCP/DNS/TLS/HTTP recovery.

### Changed

- Preserve packet timestamps, lengths, link types, and capture-loss accounting across live capture and export, with configurable snap length, promiscuous mode, and BPF filters.
- Keep sustained captures responsive with bounded disk spooling and incremental session updates.

## [0.2.0] - 2026-08-13

### Added

- Add Tracexy demo captures
- Add update badge and inspector detail tables
- Add session export actions

### Fixed

- Harden live frame ingestion

### Changed

- Refine session search and assistant dock
- Streamline security investigation

## [0.1.4] - 2026-08-06

### Changed

- Make force reset authorization-safe

## [0.1.3] - 2026-08-06

### Changed

- Recover service registration after app updates

## [0.1.2] - 2026-08-05

### Fixed

- Stabilize live session table updates

## [0.1.1] - 2026-07-31

### Fixed

- Harden lifecycle recovery

## [0.1.0] - 2026-07-31

### Added

- Capture → protocol → session foundation: privileged capture helper, PCAP/PCAPNG IO, direct packet decoding, batch session summaries, and native UI.
- App-level capacity limits are resolved from an injected `AppPolicy` at launch rather than hardcoded: workspace tabs, saved focus sets, and pinned hosts. Reaching a limit now explains itself instead of doing nothing.
- Settings now uses native toolbar tabs, consistent grouped cards, semantic Light/Dark surfaces, and tighter field and status layouts across every pane.
- Sparkle 2 provides signed Community updates through the public appcast, with one app-owned updater shared by the app menu and Settings, automatic-check/download preferences backed directly by Sparkle, and local builds kept manual-only.

### Fixed

- Improved the description shown for unencrypted HTTP traffic.

### Changed

- Helper compatibility now reads the bundled helper version, build, and protocol from the shared release version configuration instead of assuming they match the app version.
