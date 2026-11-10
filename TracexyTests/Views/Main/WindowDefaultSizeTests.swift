import Foundation
import Testing
@testable import Tracexy

// MARK: - WindowDefaultSizeTests

/// A window scene's `defaultSize` and its content view's declared minimum are
/// two statements about the same window, and they can disagree.
///
/// When the default is smaller than the minimum the window cannot open at the
/// size it declares: it comes up clamped to the minimum, and a table inside it
/// starts with its columns squeezed below the ideal widths they ask for.
/// Measured 2026-11-07: Manage Interfaces declared a 760pt default against an
/// 820pt minimum, while its columns' ideal widths total about 730pt.
///
/// This reads the source rather than opening windows, so it holds on a host
/// with no GUI automation.
struct WindowDefaultSizeTests {
    // MARK: Internal

    @Test
    func everyWindowCanOpenAtTheSizeItDeclares() throws {
        let scenes = try Self.scenes(in: readProjectFile("Tracexy/TracexyApp.swift"))
        #expect(scenes.count >= 15, "The scene parse must find the window scenes, not a handful")

        let minimums = try Self.minimums(of: scenes.map(\.view))
        for scene in scenes {
            guard let minimum = minimums[scene.view] else {
                continue
            }
            #expect(
                scene.width >= minimum.width,
                "\(scene.name) opens \(scene.width)pt wide against a \(minimum.width)pt minimum in \(scene.view)"
            )
            #expect(
                scene.height >= minimum.height,
                "\(scene.name) opens \(scene.height)pt tall against a \(minimum.height)pt minimum in \(scene.view)"
            )
        }
    }

    // MARK: Private

    private struct Scene {
        let name: String
        let view: String
        let width: Int
        let height: Int
    }

    private struct Size {
        let width: Int
        let height: Int
    }

    private var projectRoot: URL {
        var url = URL(fileURLWithPath: #filePath)
        while url.lastPathComponent != "TracexyTests", url.path != "/" {
            url.deleteLastPathComponent()
        }
        url.deleteLastPathComponent()
        return url
    }

    /// Each `Window("…") { SomeView(…) } .defaultSize(width:height:)` in the app.
    private static func scenes(in source: String) throws -> [Scene] {
        let pattern = #"Window\("([^"]+)",[^\n]*\n(.*?)\.defaultSize\(width: ([\d_]+), height: ([\d_]+)\)"#
        let regex = try NSRegularExpression(pattern: pattern, options: .dotMatchesLineSeparators)
        let whole = NSRange(source.startIndex ..< source.endIndex, in: source)
        return regex.matches(in: source, range: whole).compactMap { match in
            guard let name = source.substring(match.range(at: 1)),
                  let body = source.substring(match.range(at: 2)),
                  let width = source.substring(match.range(at: 3)).flatMap(Self.number),
                  let height = source.substring(match.range(at: 4)).flatMap(Self.number),
                  let view = Self.rootView(of: body) else
            {
                return nil
            }
            return Scene(name: name, view: view, width: width, height: height)
        }
    }

    /// The first view type the scene builds, which is the one whose frame the
    /// window takes its minimum from.
    private static func rootView(of body: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: #"(\w+(?:Window|View|Pane))\s*\("#) else {
            return nil
        }
        let whole = NSRange(body.startIndex ..< body.endIndex, in: body)
        guard let match = regex.firstMatch(in: body, range: whole) else {
            return nil
        }
        return body.substring(match.range(at: 1))
    }

    /// `.frame(minWidth:minHeight:)` from each named view's own file.
    private static func minimums(of views: [String]) throws -> [String: Size] {
        var found: [String: Size] = [:]
        let regex = try NSRegularExpression(pattern: #"\.frame\(minWidth: ([\d_]+), minHeight: ([\d_]+)\)"#)
        for view in Set(views) {
            guard let source = try? sourceOfView(named: view) else {
                continue
            }
            let whole = NSRange(source.startIndex ..< source.endIndex, in: source)
            guard let match = regex.firstMatch(in: source, range: whole),
                  let width = source.substring(match.range(at: 1)).flatMap(Self.number),
                  let height = source.substring(match.range(at: 2)).flatMap(Self.number) else
            {
                continue
            }
            found[view] = Size(width: width, height: height)
        }
        return found
    }

    private static func number(_ text: String) -> Int? {
        Int(text.replacingOccurrences(of: "_", with: ""))
    }

    /// `<view>.swift` anywhere under the product's view tree.
    private static func sourceOfView(named view: String) throws -> String {
        var root = URL(fileURLWithPath: #filePath)
        while root.lastPathComponent != "TracexyTests", root.path != "/" {
            root.deleteLastPathComponent()
        }
        root.deleteLastPathComponent()
        let views = root.appendingPathComponent("Tracexy/Views")
        guard let walk = FileManager.default.enumerator(at: views, includingPropertiesForKeys: nil) else {
            throw CocoaError(.fileNoSuchFile)
        }
        for case let url as URL in walk where url.lastPathComponent == "\(view).swift" {
            return try String(contentsOf: url, encoding: .utf8)
        }
        throw CocoaError(.fileNoSuchFile)
    }

    private func readProjectFile(_ relativePath: String) throws -> String {
        try String(contentsOf: projectRoot.appendingPathComponent(relativePath), encoding: .utf8)
    }
}

// MARK: - String range helper

private extension String {
    func substring(_ range: NSRange) -> String? {
        Range(range, in: self).map { String(self[$0]) }
    }
}
