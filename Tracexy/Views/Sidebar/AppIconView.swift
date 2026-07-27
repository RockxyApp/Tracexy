import AppKit
import SwiftUI

/// Renders an app icon: the real NSWorkspace icon when the app can be resolved
/// by name, otherwise a gradient monogram fallback.
struct AppIconView: View {
    // MARK: Internal

    let name: String
    var size: CGFloat = 16

    var body: some View {
        if let icon = Self.resolvedIcon(for: name, size: size) {
            Image(nsImage: icon)
                .resizable()
                .interpolation(.high)
                .frame(width: size, height: size)
        } else {
            RoundedRectangle(cornerRadius: 4)
                .fill(gradient)
                .frame(width: size, height: size)
                .overlay {
                    Text(letter)
                        .font(.system(size: max(9, size * 0.6), weight: .bold, design: .rounded))
                        .foregroundStyle(.white)
                }
        }
    }

    // MARK: Private

    private struct IconCacheKey: Hashable {
        let name: String
        let size: Int
    }

    private static var iconCache: [String: NSImage] = [:]
    private static var resizedIconCache: [IconCacheKey: NSImage] = [:]
    private static var missingIconNames: Set<String> = []

    private static let bundleIDMap: [String: String] = [
        "Chrome": "com.google.Chrome",
        "Google Chrome": "com.google.Chrome",
        "Safari": "com.apple.Safari",
        "Firefox": "org.mozilla.firefox",
        "Slack": "com.tinyspeck.slackmacgap",
        "Xcode": "com.apple.dt.Xcode",
        "Spotify": "com.spotify.client",
        "Discord": "com.hnc.Discord",
        "Arc": "company.thebrowser.Browser",
        "Brave Browser": "com.brave.Browser",
        "Microsoft Edge": "com.microsoft.edgemac",
        "Figma": "com.figma.Desktop",
        "Postman": "com.postmanlabs.mac",
    ]

    private var letter: String {
        String(name.prefix(1)).uppercased()
    }

    private var gradient: LinearGradient {
        // Deterministic per-name hue so the same process keeps the same color.
        let hue = Double(abs(name.hashValue) % 360) / 360.0
        return LinearGradient(
            colors: [
                Color(hue: hue, saturation: 0.55, brightness: 0.85),
                Color(hue: hue, saturation: 0.65, brightness: 0.60),
            ],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
    }

    private static func resolvedIcon(for name: String, size: CGFloat) -> NSImage? {
        let cacheKey = IconCacheKey(name: name, size: Int(size.rounded()))
        if let cached = resizedIconCache[cacheKey] {
            return cached
        }
        guard let source = resolveIconSource(for: name),
              let icon = source.copy() as? NSImage else
        {
            return nil
        }
        icon.size = NSSize(width: size, height: size)
        resizedIconCache[cacheKey] = icon
        return icon
    }

    private static func resolveIconSource(for name: String) -> NSImage? {
        guard !name.isEmpty, name != "—", !missingIconNames.contains(name) else {
            return nil
        }
        if let cached = iconCache[name] {
            return cached
        }

        if let bundleID = bundleIDMap[name],
           let appURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID)
        {
            let icon = NSWorkspace.shared.icon(forFile: appURL.path)
            iconCache[name] = icon
            return icon
        }

        for path in ["/Applications/\(name).app", "/System/Applications/\(name).app"] {
            if FileManager.default.fileExists(atPath: path) {
                let icon = NSWorkspace.shared.icon(forFile: path)
                iconCache[name] = icon
                return icon
            }
        }

        for app in NSWorkspace.shared.runningApplications where app.localizedName == name {
            if let icon = app.icon {
                iconCache[name] = icon
                return icon
            }
        }

        missingIconNames.insert(name)
        return nil
    }
}
