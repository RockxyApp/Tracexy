# Design QA — Rockxy-style expanded session filters

## Evidence

- Source visual truth: attached
  `codex-clipboard-14500abe-29e4-45aa-93d6-2a855bc47447.png`.
- Rebuilt implementation screenshot: `tracexy-expanded-filter-rockxy-style-window.jpg`
  in the external runtime QA capture folder.
- Focused implementation crop: `tracexy-expanded-filter-rockxy-style.jpg` in the same
  external runtime QA capture folder.
- Combined source/implementation comparison:
  `tracexy-expanded-filter-rockxy-style-comparison.png` in the same external runtime QA
  capture folder.
- Viewport: native macOS window, 1299 × 768 screenshot pixels, Light appearance.
- Source pixels: 1938 × 263 at Retina density; normalized source: 969 × 132.
  Focused implementation pixels: 1090 × 88; normalized comparison width: 969.
- State: empty Sessions workspace with the advanced filter visible and three enabled,
  blank rules, matching the reference's expanded three-row state.

## Findings

- No actionable P0, P1, or P2 mismatch remains for the expanded-filter request.
- Spacing and layout rhythm: the editor is now the third full-width surface in the same
  glass group, with the shared 16-point radius and 7-point shelf cadence. Its columns,
  12-point row inset, 10-point row spacing, and 8/4-point top rhythm match Rockxy while
  retaining Tracexy's narrow-window `ViewThatFits` fallback.
- Fonts and typography: native SF roles remain intact; repeated row actions use compact
  medium-weight SF Symbols, while Where, AND/OR, field, operator, value, and Presets stay
  explicit text-bearing controls.
- Colors and tokens: checkbox, segmented selection, semantic disabled opacity, and the
  neutral Tracexy material all use shared system tokens. Rockxy's blue sampling cast is
  product-background context, not a hard-coded color copied into Tracexy.
- Image quality and asset fidelity: all visible symbols are native SF Symbols and remain
  sharp at the captured density; no raster approximations or custom drawings were added.
- Copy and content: Tracexy correctly uses session fields such as Host rather than
  importing Rockxy's proxy-specific URL vocabulary. The Rockxy shortcut footer is
  intentionally omitted because Tracexy does not yet implement its row-selection
  commands; advertising those shortcuts would be false UI.

## Full-view comparison

The rebuilt native window confirms the advanced editor expands below the protocol shelf
without nesting another material, shifting the sidebar anchor, clipping the session
viewport, or disturbing the command/search rows.

## Focused comparison

The density-normalized combined comparison confirms the same rule hierarchy and visual
grammar: checkbox, Where/connector, field, operator, flexible value, compact glass minus
and plus actions, and the single first-row Presets menu. The different field names and
missing shortcut footer are intentional product/behavior constraints.

## Comparison history

- Pass 1: source and implementation inspection found the Tracexy editor was an opaque
  content card outside the shared shelf group, with borderless row mutation icons.
- Pass 2: the editor moved into the shared glass container as a third rounded surface;
  plus/minus adopted small native glass actions, and the columns were aligned to the
  Rockxy row rhythm while retaining Tracexy's stronger cap and single-row safeguards.
- Pass 3: the rebuilt application was exercised from Add Field through a three-row state.
  The focused comparison and accessibility tree show no remaining P0/P1/P2 issue.

## Follow-up polish

- P3: add a compact shortcut footer only after Tracexy has a truthful focused-rule
  command model; separately repeat the capture in Dark Mode and Increased Contrast.

final result: passed
