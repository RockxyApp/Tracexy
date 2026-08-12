# Design QA — Rockxy-aligned Tracexy workspace chrome

Date: 2026-08-12

## Source visual truth

- Search/filter reference: native Rockxy search row captured in its no-traffic state.
- AI Assistant reference: native Rockxy assistant dock captured in its no-selection state.
- Both references are native Rockxy captures at 1292 × 768 pixels in their no-traffic/no-selection states.

## Rendered implementation

- Search/filter implementation: native Tracexy Debug capture after responsive-control refinement.
- AI Assistant implementation: native Tracexy Debug capture with the empty conversation shell visible.
- AI Assistant privacy state: native Tracexy Debug capture with the trust-boundary popover visible.
- The Tracexy captures are native Debug-app captures at 1179 × 768 pixels. Both products use the same native macOS density and 768-pixel window height; the width difference comes from their saved window frames. Comparison therefore uses the full window for hierarchy and the shared 320-point inspector/search regions for control-level fidelity rather than stretching either capture.

## Comparison state and evidence

- Search comparison: Sessions/traffic surface, no captured traffic, search enabled, default field selected, Details inspector visible.
- Assistant comparison: Sessions/traffic surface, no selected traffic, AI Assistant tab selected, empty conversation and pinned composer visible.
- Full-view comparison confirms the same vertical control hierarchy and compact density: protocol filters, checkbox, native scope picker, flexible rounded search, divider, bordered add action, and trailing disclosure.
- The assistant now follows the same header → attached-context row → transcript → composer hierarchy as the reference. Tracexy intentionally marks history, new conversation, prompt, and send unavailable because its assistant subsystem is not implemented.
- Focused crops were not required: at the captured 1× native resolution, the complete search row and 320-point assistant dock are readable without scaling. Accessibility-tree inspection separately confirmed names, disabled states, help text, and the working Read-only popover.

## Required fidelity surfaces

- Fonts and typography: both products use native SF Pro through SwiftUI semantic text styles. Header/body/caption weights, one-line truncation, and compact control text match the reference hierarchy.
- Spacing and layout rhythm: search uses 8-point gaps, 130/100-point responsive picker tiers, a 220-point minimum flexible field, and an 18-point divider. Assistant uses 36-point header, 32-point context row, 10-point content inset, native dividers, and a 10-point composer radius.
- Colors and tokens: implementation uses semantic AppKit window, text-background, separator, primary, secondary, accent, and status colors; light/dark appearance remains system-driven.
- Image and icon fidelity: there are no raster assets in either target region. All icons are native SF Symbols; no placeholder art, custom SVG, or improvised glyph was introduced.
- Copy and content: Tracexy retains its session-specific `All Fields` semantics and the requested `Add Field` copy. Assistant copy is product-specific and explicitly states that no backend/model is connected instead of imitating working Rockxy capabilities.

## Findings and comparison history

- First assistant comparison found one P1 placement defect: the 320-point Read-only popover opened beyond the right window edge and clipped its copy.
- Fix: changed the native popover anchor edge so it opens to the left of the footer control.
- Post-fix evidence confirms the full popover remains inside the window with all copy and rows visible.
- Final comparison found no remaining actionable P0, P1, or P2 differences. Disabled history/model behavior is an intentional capability constraint, not visual drift.

## Interactions verified

- Details/AI Assistant segmented switching.
- `Add Field` remains visible at the normal window width and has an accessible name/help description.
- `All Fields` remains the default native pop-up selection.
- Read-only privacy control opens a fully visible trust-boundary popover.
- Assistant history, new conversation, prompt, and send are visibly and accessibly unavailable; no simulated transcript or model output appears.

## Automated checks

- Debug macOS build: passed.
- Focused search semantics and presentation-contract tests: passed.
- Full `TracexyTests` unit suite: passed.
- SwiftFormat lint: passed (0 files require formatting).
- SwiftLint strict: passed (0 violations).
- Git whitespace/error check: passed.

## Follow-up polish

- No P3 visual issue is being carried forward for these states. Full conversation history, recipes, streaming, and model controls remain future product functionality and should only appear with a typed assistant subsystem and its safety tests.

final result: passed
