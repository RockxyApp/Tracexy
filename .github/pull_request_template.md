## Summary

-

## Validation

- [ ] `swiftformat --lint .`
- [ ] `swiftlint lint --strict`
- [ ] `xcodebuild -project Tracexy.xcodeproj -scheme Tracexy -destination 'platform=macOS' build`
- [ ] Relevant tests:

## Safety Checklist

- [ ] Targets `develop`.
- [ ] Includes tests or explains why tests are not applicable.
- [ ] Updates docs for user-facing behavior changes.
- [ ] Preserves capture/helper/XPC/privacy boundaries.
- [ ] Contains no credentials, signing files, local paths, raw captures, or private config.
- [ ] Does not use agent, model, vendor, or local tool identity in public metadata.
- [ ] I have read and agree to the Tracexy ICLA v1.0.

## Notes

-
