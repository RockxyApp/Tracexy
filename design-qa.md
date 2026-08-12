# Design QA — toolbar updates and Details inspector

Date: 2026-08-12

## Reference contract

- Update status uses the approved toolbar recipe: a 24 pt continuous capsule inside the 32 pt native toolbar control, 13 pt semibold white text, 9 pt horizontal inset, semantic system-gray fill, and a 0.75 pt low-contrast stroke.
- Details uses the approved vertical diagnostics-table recipe: 12 pt outer inset, 10 pt group gaps, control-background headers, text-background rows, native dividers, 6 pt rounded corners, and a 0.5 pt separator stroke.

## Native app verification

- Built and launched the Debug macOS app at the Sessions workspace.
- Verified the no-selection state with the Details dock open.
- Imported a generated classic-PCAP sample, selected the plaintext HTTP session, and inspected the populated Details dock in dark appearance.
- Confirmed the Assessment, Layer Details, and Flagged Here tables stay inside the dock without horizontal overflow, preserve the two-column grid, and keep technical values legible and selectable.
- Confirmed session selection still opens the bottom evidence inspector; source inspection confirms Related Action rows remain wired to coordinator selection.
- The local appcast did not report a newer release during the first run, so the conditional update badge remained hidden as intended.
- Re-launched the Debug app with `TRACEXY_UPDATE_BADGE_PREVIEW_COUNT=15` and verified the populated `15 New Updates` capsule in the native center toolbar. This fixture is compiled out of Release builds and does not alter production update telemetry.

## Automated checks

- Full `TracexyTests` suite: passed.
- Full app/UI suite: `testExample` passed; `testLaunchPerformance` stalled while Xcode waited for a macOS test-runner launch and the run was interrupted after 101 seconds. No product assertion failed.
- SwiftFormat lint: passed.
- SwiftLint strict: passed.
- `git diff --check`: passed.
