#if DEBUG

// MARK: - DemoLaunchSupport

/// Debug-build demo launches only: work the composition root may add once the
/// History demo is prepared, such as filling the isolated runtime with
/// synthetic evidence. `nil` adds nothing.
@MainActor
enum DemoLaunchSupport {
    static var afterHistoryDemo: ((MainContentCoordinator) async -> Void)?
}
#endif
