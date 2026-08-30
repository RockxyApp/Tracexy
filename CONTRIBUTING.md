# Contributing

Thanks for looking. Tracexy is early enough that a good bug report is worth as
much as a patch.

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

## Branches and pull requests

Branch from `develop` and target pull requests at `develop`. Keep one coherent
change per pull request, with docs and tests in the same review when behavior
changes.

Use product-focused branch names:

- `feat/add-pcapng-stream-note`
- `fix/helper-signature-diagnostic`
- `docs/update-security-policy`
- `test/dns-truncation-fixtures`

Do not put local agent, vendor, model, or tool names in branches, commit
subjects, pull-request titles, release notes, or authorship trailers.

Commits follow [Conventional Commits](https://www.conventionalcommits.org/):
`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, or `ci:`.

Before opening a pull request, check:

- [ ] The change is scoped to Tracexy's current source, not roadmap-only design.
- [ ] Tests were added or updated for behavior changes.
- [ ] Decoder changes cover normal, truncated, and malformed inputs.
- [ ] User-facing behavior changes update the nearest docs in `docs/`.
- [ ] Privacy, export, capture, helper, and XPC boundaries were reviewed.
- [ ] `swiftformat --lint .` and `swiftlint lint --strict` pass, or the PR
      explains why a local tool was unavailable.
- [ ] A relevant `xcodebuild` build or test command was run, or the PR explains
      why it could not be run.
- [ ] No captures, credentials, signing files, local paths, or private
      configuration were committed.

## Contributor License Agreement

External contributors must accept the current
[Tracexy Individual Contributor License Agreement v1.0](legal/cla/ICLA-v1.0.md)
before their pull request can be merged. When the CLA workflow asks, post this
exact comment on the pull request:

```text
I have read and agree to the Tracexy ICLA v1.0
```

You retain copyright in your Contribution. The ICLA gives Rockxy LLC the rights
needed to publish the Contribution in the public AGPL source edition and to use
it in separately licensed Tracexy distributions.

If your employer or another organization owns or controls your Contribution, an
authorized representative must also execute the
[Corporate Contributor License Agreement](legal/cla/CCLA-v1.0.md). Maintainers
will review organizational authorization manually.

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

## Reporting bugs

Please include the Tracexy version or commit, macOS version, whether this was a
live capture or a saved file, what interface or file type was involved, what
you expected, and what happened instead.

If a capture file reproduces it, attach one only after reviewing and redacting
it. A `.pcap` or `.pcapng` contains everything that crossed the wire, including
credentials, private hosts, and application data.

## Security

Don't open a public issue. Follow [SECURITY.md](SECURITY.md).

## License

The public source edition is licensed under
[AGPL-3.0-or-later](LICENSE). Contributions are accepted under the contributor
agreement so they can remain available in the public AGPL edition and also be
used in separately licensed Tracexy distributions. See
[Commercial Licensing Policy](legal/COMMERCIAL-LICENSING.md).
