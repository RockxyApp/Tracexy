# Design QA — single native toolbar status surface

## Evidence

- Defect reference: attached
  `codex-clipboard-d14047f7-dd92-4d21-8af5-810927475be0.png`.
- Rebuilt implementation screenshot: `tracexy-status-single-surface-window.jpg` in the
  external runtime QA capture folder.
- Focused implementation crop: `tracexy-status-single-surface.png` in the same folder.
- Combined before/after comparison: `tracexy-status-single-surface-comparison.png` in
  the same folder.
- Viewport: native macOS window, 1299 × 768 screenshot pixels, Dark appearance.
- Defect-reference pixels: 474 × 98. Focused implementation pixels: 480 × 80.
- State: empty Sessions workspace, Wi-Fi (`en0`) selected, capture stopped.

## Findings

- No actionable P0, P1, or P2 mismatch remains for the overlapping status surfaces.
- Surface ownership: the unified native `NSToolbar` now owns the only visible capsule;
  the hosted SwiftUI status content supplies hit geometry but no second glass material.
- Fonts and typography: Tracexy, interface, and capture-state labels retain the existing
  semantic toolbar typography and single-line truncation behavior.
- Spacing and layout rhythm: the centered status remains balanced between flexible
  toolbar regions, with the dot, separators, text, and caret retaining their approved
  spacing.
- Colors and tokens: the stopped dot remains tertiary and receives no semantic glow;
  the native toolbar controls material, border, elevation, and appearance adaptation.
- Interaction and accessibility: activating Capture Readiness still opens its popover;
  the status value remains `Tracexy | en0 | Stopped`, and the update badge remains a
  separate action when present.

## Full-view comparison

The rebuilt native window confirms the correction is isolated to the centered status
item. Sidebar, session command shelf, protocol filters, table viewport, and trailing
toolbar actions remain in place.

## Focused comparison

The combined comparison shows the prior nested inner/outer glass outlines and the
rebuilt result with one restrained native toolbar capsule.

## Comparison history

- Pass 1: the defect capture exposed a SwiftUI interactive glass capsule nested inside
  an AppKit unified toolbar item, producing two dim outlines and duplicated elevation.
- Pass 2: the explicit SwiftUI glass layer was removed while preserving a capsule
  content shape. The rebuilt Dark appearance capture and live popover activation confirm
  one native surface and unchanged behavior.

## Follow-up polish

- None for this scoped correction.

final result: passed
