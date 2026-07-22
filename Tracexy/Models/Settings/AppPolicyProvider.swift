import Foundation

// MARK: - AppPolicyProvider

/// Resolves the ``AppPolicy`` this build runs under.
///
/// This is the one place a build decides its limits. Everything downstream —
/// the coordinator, the stores, the gates — receives the resolved values and
/// has no way to ask which build it is running in. Keeping the question here
/// means no call site ever has to answer it.
enum AppPolicyProvider {
    static let current: any AppPolicy = DefaultAppPolicy()
}
