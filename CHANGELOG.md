# Changelog

All notable changes to Tracexy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- Capture → protocol → session foundation: privileged capture helper, PCAP/PCAPNG IO, direct packet decoding, batch session summaries, and native UI.
- App-level capacity limits are resolved from an injected `AppPolicy` at launch rather than hardcoded: workspace tabs, saved focus sets, and pinned hosts. Reaching a limit now explains itself instead of doing nothing.
