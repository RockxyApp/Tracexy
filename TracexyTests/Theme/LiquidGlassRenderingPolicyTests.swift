import Foundation
import Testing
@testable import Tracexy

@Suite("Liquid Glass rendering policy")
@MainActor
struct LiquidGlassRenderingPolicyTests {
    // MARK: Internal

    @Test("Native Liquid Glass is selected only when available")
    func availabilitySelectsNativeGlass() {
        #expect(LiquidGlassRenderingPolicy.resolve(
            liquidGlassAvailable: true,
            reduceTransparency: false,
            increaseContrast: false
        ) == .liquidGlass)
        #expect(LiquidGlassRenderingPolicy.resolve(
            liquidGlassAvailable: false,
            reduceTransparency: false,
            increaseContrast: false
        ) == .systemMaterial)
    }

    @Test("Accessibility preferences always select an opaque surface", arguments: [
        (true, false),
        (false, true),
        (true, true),
    ])
    func accessibilityWins(reduceTransparency: Bool, increaseContrast: Bool) {
        #expect(LiquidGlassRenderingPolicy.resolve(
            liquidGlassAvailable: true,
            reduceTransparency: reduceTransparency,
            increaseContrast: increaseContrast
        ) == .opaqueColor)
        #expect(LiquidGlassRenderingPolicy.resolve(
            liquidGlassAvailable: false,
            reduceTransparency: reduceTransparency,
            increaseContrast: increaseContrast
        ) == .opaqueColor)
    }

    @Test("Appearance identity changes for every sampled rendering input")
    func appearanceIdentityCoversRenderingInputs() {
        let baseline = LiquidGlassAppearanceIdentity(
            isDark: false,
            reduceTransparency: false,
            increaseContrast: false
        )

        #expect(baseline != LiquidGlassAppearanceIdentity(
            isDark: true,
            reduceTransparency: false,
            increaseContrast: false
        ))
        #expect(baseline != LiquidGlassAppearanceIdentity(
            isDark: false,
            reduceTransparency: true,
            increaseContrast: false
        ))
        #expect(baseline != LiquidGlassAppearanceIdentity(
            isDark: false,
            reduceTransparency: false,
            increaseContrast: true
        ))
    }

    @Test("macOS 26 presentation APIs retain compiler gates")
    func nativePresentationAPIsAreCompilerGated() throws {
        let source = try readProjectFile("Tracexy/Theme/LiquidGlass.swift")
        #expect(source.contains("#if compiler(>=6.2)"))
        #expect(source.contains("#available(macOS 26.0, *)"))
        #expect(source.contains("GlassEffectContainer"))
        #expect(source.contains("content.safeAreaBar(edge: .top"))
        #expect(source.contains("content.scrollEdgeEffectStyle(.hard"))
        #expect(source.contains("content.scrollEdgeEffectStyle(.soft"))
    }

    @Test("Theme changes refresh existing AppKit toolbar hosts")
    func themeChangesRefreshToolbarHosts() throws {
        let source = try readProjectFile("Tracexy/Theme/Theme.swift")

        #expect(source.contains("refreshExistingWindowChrome(with: resolvedAppearance)"))
        #expect(source.contains("toolbar.visibleItems"))
        #expect(source.contains("refreshToolbarView(subview, appearance: appearance)"))
        #expect(source.contains("DispatchQueue.main.async"))
    }

    // MARK: Private

    private var projectRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func readProjectFile(_ relativePath: String) throws -> String {
        try String(contentsOf: projectRoot.appendingPathComponent(relativePath), encoding: .utf8)
    }
}
