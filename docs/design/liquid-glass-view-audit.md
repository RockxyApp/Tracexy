# Liquid Glass view audit

Audited 2026-08-24 against the production `Tracexy/Views` tree and every app scene in `TracexyApp.swift`. This inventory is exhaustive for current source. It distinguishes functional chrome from data content so “more glass” never becomes glass behind packet text, tables or evidence.

Toolbar entries reconciled 2026-09-04: Project context and capture-source controls now have separate native toolbar ownership and responsive interface labeling.

## Window and split hierarchy

| Source | Disposition |
| --- | --- |
| `TracexyApp.swift` | The main workspace keeps a hidden semantic title with a unified native toolbar, so no view title or tagline displaces the Project selector. Settings, Focus Set and Noise Control remain titled Mac windows. |
| `Common/NativeWorkspaceWindowChrome.swift` | Hidden semantic title, unified toolbar, standalone leading Project selector, centered status, trailing interface picker beside Start/Stop, then a native gap before Export and grouped inspector controls. |
| `Common/CaptureInterfaceToolbarPicker.swift` | Native menu with a bounded friendly interface label, icon-only at compact widths, and full interface identity retained in the menu, tooltip and accessibility value. Hosting constraints preserve spacing across resize round trips. |
| `Projects/ProjectPresentation.swift` | Standalone native Project menu and management sheets; bounded configuration-only content stays separate from capture-source controls. |
| `Main/NativeWorkspaceSplitView.swift` | Native sidebar, workspace and trailing inspector split items; owns resizing and collapse semantics. |
| `Main/NativeBottomInspectorSplitView.swift` | Native resizable evidence inspector below the session workspace. |
| `Main/RootView.swift` | Owns toolbar controls, top session command safe-area bar and bottom status safe-area bar. |

## Shared chrome and tokens

| Source | Disposition |
| --- | --- |
| `Common/WorkspaceChromeStyles.swift` | Native equal-width `NSSegmentedControl` bridge and shared mode-switch geometry. |
| `Common/WorkspaceFooterBar.swift` | Glass only in the center workspace; transparent in semantic sidebar/inspector panes to prevent glass-on-glass. |
| `Theme/LiquidGlass.swift` | macOS 26 native glass, safe-area bars, scroll-edge effects, shared containers and accessibility fallbacks. |

## Primary workspace surfaces

| Source | Functional chrome | Content treatment |
| --- | --- | --- |
| `Overview/OverviewView.swift` | Native safe-area header and hard scroll edge; no decorative rounded glass behind its title. | Dashboard metrics and findings stay readable content surfaces. |
| `Sessions/SessionCenterView.swift` | Safe-area filter/control shelf with hard scroll edge. | Native `Table`, empty states and progress notices remain content. |
| `Sessions/SessionCommandBar.swift` | Adjacent native glass controls share one container; no glass parent behind glass buttons. | No data content. |
| `Sessions/SessionFilterBar.swift` | One shared command/filter glass group with separate command, category, and expanded-rule surfaces; native search/pickers plus semantic chips. | Advanced rule values remain standard controls; only repeated row mutation actions use compact glass buttons. |
| `Sessions/StructuredFilterBar.swift` | Glass add/remove actions and functional preset controls. | Dense rule rows remain opaque content surfaces. |
| `Sessions/SessionStatusBar.swift` | Read-only telemetry in the workspace glass footer. | No fabricated metrics; semantic colors remain system colors. |
| `Sessions/InvestigationQueryView.swift` | Safe-area glass header and action footer. | Query rows remain opaque because they carry dense editable data. |
| `Sessions/RealtimeChart.swift` | No independent glass; it belongs inside the session control shelf. | Chart marks stay content. |
| `Sessions/SessionHistoryScrollObserver.swift` | Infrastructure only; no presentation. | Not applicable. |
| `Flow/FlowMapView.swift` | Native safe-area scope header; the standalone focus action retains native control treatment. | Endpoint list, graph marks and labels stay content. |
| `History/HistoryView.swift` | Native safe-area header with one consistent small-control action cluster. | Native sidebar list and history session details remain content; obsolete hand-painted material removed. |

## Navigation, Details and evidence

| Source | Functional chrome | Content treatment |
| --- | --- | --- |
| `Sidebar/SidebarView.swift` | Native segmented mode switcher in top safe-area; native search/add footer in bottom safe-area. | Source-list rows remain native `.sidebar` content. |
| `Sidebar/SidebarBottomBar.swift` | Native `NSSearchField`, menu and transparent semantic-sidebar footer. | No independent data content. |
| `Sidebar/AppIconView.swift` | Branded asset only; not a glass surface. | Existing icon artwork retained. |
| `Inspector/ContextDockView.swift` | Native segmented tab safe-area and transparent inspector footer. | Details cards/tables stay readable content. |
| `Inspector/AIAssistantDockView.swift` | Safe-area conversation header and interactive glass composer. | Transcript is content; disconnected/read-only truth remains explicit. |
| `Inspector/InspectorView.swift` | Safe-area facet/filter shelf and hard scroll edge without a second rounded material behind its semantic chips. | Layers, bytes, stream and decoded fields stay opaque content. |
| `Inspector/ContextInspectorTable.swift` | No independent chrome. | Dense fact tables use shared content surfaces. |
| `Inspector/DecodedClipboardText.swift` | Pure clipboard formatting; no presentation. | Not applicable. |

## Settings, prompts and auxiliary windows

| Source | Disposition |
| --- | --- |
| `Settings/SettingsView.swift` | Native `NavigationSplitView` and sidebar list replace the old tab shell. |
| `Settings/SettingsStyle.swift` | Shared headings, rows, badges, dividers and content cards; selected theme control is interactive glass without white-on-accent text. |
| `Settings/GeneralSettingsView.swift` | Native forms and controls inside Settings content. |
| `Settings/CaptureSettingsView.swift` | Native capture controls inside Settings content. |
| `Settings/PrivacySettingsView.swift` | Native privacy controls inside Settings content. |
| `Settings/HelperSettingsView.swift` | Native helper status/actions inside Settings content. |
| `Settings/UpdatesSettingsView.swift` | Native update status/actions inside Settings content. |
| `Settings/MCPSettingsView.swift` | Truthful planned-state content; no fake glass service status. |
| `Settings/HelperRecoveryPresenter.swift` | Presentation bridge only; no custom surface. |
| `Helper/HelperInstallPromptView.swift` | Native sheet structure, safe-area header/footer, one shared title scale and standalone glass actions. |
| `Toolbar/CaptureReadinessPopover.swift` | Native popover structure, scrollable facts, safe-area header/footer and standalone glass actions. |
| `Sidebar/FocusSetEditorWindow.swift` | Native titlebar, safe-area name/action rows and consistent glass add/save/cancel controls; inline rule removal stays borderless. |
| `Sidebar/NoiseControlWindow.swift` | Native titled window with Clear All in the real toolbar and a minimal glass Done action; mute rules remain native list content. |

## Review rules

- New functional bars must first prove why a standard toolbar, sidebar, inspector or safe-area bar is insufficient.
- Never add glass behind packet bytes, table rows, decoded fields, stream payload, settings prose or other dense content.
- Never nest custom `glassEffect` surfaces. A deliberate control shelf may place native glass buttons
  inside the same `TracexyGlassEffectGroup`; do not wrap that shelf in `tracexyFunctionalBar()` or add
  another custom glass-card layer.
- Every visible text font must resolve through `Theme.Typography` (or the Settings adapter backed by it); direct per-view sizes are reserved for SF Symbols and the app-icon monogram.
- Every new production view must be added to this inventory and exercised in Light, Dark, Reduce Transparency and Increase Contrast paths.
