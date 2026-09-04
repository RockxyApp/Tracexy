# Tracexy UI implementation contract

This contract describes the current native macOS presentation boundary. Product behavior, capture semantics and privacy rules remain owned by the typed application layers; views only project those values.

## Native structure

- Keep the root window on native AppKit split items and toolbar hosting.
- Keep navigation in `List(.sidebar)` and session data in the existing native `Table` path. Do not replace selection, resizing, focus, menus or keyboard behavior with painted lookalikes.
- Keep the right Details inspector and bottom evidence inspector as independently resizable native split regions.
- Seat functional top and bottom chrome with `safeAreaBar`; allow scrollable content to continue underneath it and choose one deliberate scroll-edge style per pane. Do not add another rounded glass background merely because content sits in a safe-area bar.
- Keep the main window title semantic but hidden. Surface titles and the product tagline must never enter the toolbar or displace the leading Project selector. Keep capture status centered, the capture-interface picker beside Start/Stop on the trailing side, and a native gap before Export and inspector controls.
- Preserve semantic SF Symbols, system type styles and system colors across Light, Dark and accessibility appearances.

## Liquid Glass policy

Liquid Glass is reserved for functional chrome: command bars, filter shelves, compact headers, footer controls and closely related interactive controls. On macOS 26, these surfaces use the native Liquid Glass APIs. Older supported releases use system material. Reduce Transparency or Increase Contrast always overrides both with an opaque adaptive system surface.

The hierarchy is semantic structure → safe-area chrome → controls. A sidebar or inspector already receives its platform material from the split-view structure, so its footer and picker remain transparent/native instead of sampling another glass surface. Adjacent custom glass controls share a `GlassEffectContainer`; a parent glass surface and glass-styled child controls are mutually exclusive.

Every custom glass instance is keyed from Light/Dark, Reduce Transparency and Increase Contrast so changing appearance recreates any sampled effect. Existing AppKit windows and toolbar-hosted views are explicitly refreshed when the app appearance changes.

Information-dense content remains opaque. Tables, packet bytes, stream payloads, inspector field groups and query rows use `tracexyContentSurface(...)`; semantic states use `tracexyChipStyle(...)`. Do not nest glass cards, paint extra shadows around native glass, or place low-contrast text over sampled content.

## Shared implementation surface

- `Tracexy/Theme/LiquidGlass.swift` owns availability, accessibility and rendering decisions.
- `Theme.Glass` owns shared geometry and opacity tokens.
- `tracexyFunctionalBar()` is reserved for a bounded custom control shelf that cannot be expressed by native toolbar or safe-area structure.
- `tracexyGlassEffect(...)` and `TracexyGlassEffectGroup` are for bounded custom functional surfaces.
- `tracexyGlassButtonStyle(...)` keeps platform-native button behavior.
- `tracexySafeAreaBar(...)` owns top/bottom edge placement and the older-system structural fallback.
- `tracexyDenseScrollEdge()` and `tracexySoftScrollEdge()` distinguish pinned data chrome from navigation chrome.
- `tracexyChromeContentClearance(...)` is reserved for fixed AppKit split children that do not consume propagated safe-area insets; it must not be added to ordinary SwiftUI scroll views.
- `tracexyContentSurface(...)` is the readable counterpart for dense data.
- `tracexyChipStyle(...)` owns hover, active, disabled and contrast-aware semantic pills.

## Review checklist

1. Build against the current macOS SDK while retaining compiler and runtime gates for macOS 26-only APIs.
2. Verify Dark and Light appearance transitions in an already-open window, including native toolbar hosts.
3. Exercise the main Overview, Sessions, Flow Map, History, Details, evidence inspector and Settings paths at compact and wide window sizes.
4. Unit-test the rendering decision matrix, appearance identity and source-level native-structure contracts.
5. Run SwiftFormat/SwiftLint plus the relevant unit and full UI suites. Any UI-runner infrastructure failure must be reported separately from product defects.
6. Reject any production view that bypasses `Theme.Typography` for visible text or nests `tracexyGlassButtonStyle` inside `tracexyFunctionalBar`.

The view-by-view disposition is recorded in `docs/design/liquid-glass-view-audit.md`; update it whenever a new production view or window is added.
