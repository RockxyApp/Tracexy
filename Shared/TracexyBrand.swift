import Foundation

extension TracexyIdentity {
    static var productName: String {
        "Tracexy"
    }

    static var tagline: String {
        "Native macOS Network Intelligence Platform"
    }

    /// Static convenience over the resolved current identity.
    static var helperBundleIdentifier: String {
        current.helperBundleIdentifier
    }
}
