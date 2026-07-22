# Contributing

Thanks for looking. Tracexy is early enough that a good bug report is worth as much as a patch.

By participating you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Setup

macOS 14+, Xcode 16+, [SwiftLint](https://github.com/realm/SwiftLint), and
[SwiftFormat](https://github.com/nicklockwood/SwiftFormat).

```bash
git clone https://github.com/RockxyApp/Tracexy.git
cd Tracexy
cp Configuration/Developer.xcconfig.template Configuration/Developer.xcconfig
```

Fill in your own Team ID in `Configuration/Developer.xcconfig`. It is gitignored — never commit it.

```bash
xcodebuild -project Tracexy.xcodeproj -scheme Tracexy -destination 'platform=macOS' build
xcodebuild -project Tracexy.xcodeproj -scheme Tracexy -destination 'platform=macOS' test
```

The project uses Xcode's file-system-synchronized groups, so adding a Swift file under `Tracexy/`
or `TracexyTests/` needs no project-file edit. Create the file and build.

## Code style

`.swiftlint.yml` and `.swiftformat` are the source of truth — run them rather than arguing with
them:

```bash
swiftformat . && swiftlint lint --strict
```

The short version: 4-space indent, ~120-character lines, explicit access control, `final` by
default, no force unwraps or force casts, `// MARK:` sectioning. `@Observable` rather than
`ObservableObject`. `@MainActor` for UI types, `actor` for engines. Colors, spacing, and fonts come
from `Theme` — no literal values in views. Icons are real SF Symbols via `Image(systemName:)`.

## What a good change looks like

- **Tests come with it.** Decoders especially: cover the normal packet, the truncated one, and the
  malformed one. A decoder that only handles well-formed input is not finished, because the input
  is a network.
- **`Core/` stays off the main actor and free of UI knowledge.** If your change makes a decoder
  import a view, or makes the packet path touch `@MainActor` state, it will be sent back.
- **Bounds are checked, never assumed.** Read through `PacketBuffer` and let it throw. A capture
  file is untrusted input.
- **Capacity limits are injected, not hardcoded.** If a type needs a maximum, take it as an `Int`
  in the initializer. `AppPolicy` decides the value at the composition root; nothing below it
  should be reaching for a constant or a global.
- **Small beats clever.** A summary-level feature that ships is worth more than deep decoding that
  stalls.

Commits follow [Conventional Commits](https://www.conventionalcommits.org/) — `feat:`, `fix:`,
`chore:`, `feat!:` for anything breaking. The messages drive release notes, so write them for
someone reading the changelog.

## Reporting bugs

Please include the macOS version, what you were capturing, and what you expected instead. If a
capture file reproduces it, attach one — **but redact it first.** A `.pcap` contains everything
that crossed the wire, including things you would not choose to publish.

## Security

Don't open a public issue. Follow [SECURITY.md](SECURITY.md).
