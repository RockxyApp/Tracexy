import Foundation

// MARK: - LaunchOpenOptions

/// Wireshark's launch options for a capture opened at launch
/// (`open -a Tracexy file.pcapng --args -Y "tcp and port == 443" -g 42`):
/// `-Y`/`--expression` opens it narrowed to a Session Expression and `-g`/`--frame`
/// goes to that frame. `-i`/`--interface` picks the capture interface — an
/// interface name or a named pipe's path — and `-k` starts capturing at launch
/// (`open -a Tracexy --args -i /tmp/remote.fifo -k`). Unknown arguments are ignored.
nonisolated struct LaunchOpenOptions: Equatable {
    var expression: String?
    var frame: UInt64?
    var interface: String?
    var startsCapture = false

    var isEmpty: Bool {
        expression == nil && frame == nil && interface == nil && !startsCapture
    }

    static func parse(_ arguments: [String]) -> LaunchOpenOptions {
        var options = LaunchOpenOptions()
        var index = arguments.startIndex
        while index < arguments.endIndex {
            let argument = arguments[index]
            let next = arguments.index(after: index)
            let value = next < arguments.endIndex ? arguments[next] : nil
            switch argument {
            case "-Y",
                 "--expression":
                if let value, !value.trimmingCharacters(in: .whitespaces).isEmpty {
                    options.expression = value
                    index = next
                }
            case "-i",
                 "--interface":
                if let value, !value.trimmingCharacters(in: .whitespaces).isEmpty, !value.hasPrefix("-") {
                    options.interface = value.trimmingCharacters(in: .whitespaces)
                    index = next
                }
            case "-k":
                options.startsCapture = true
            case "-g",
                 "--frame":
                if let value, let frame = UInt64(value), frame > 0 {
                    options.frame = frame
                    index = next
                }
            default:
                break
            }
            index = arguments.index(after: index)
        }
        return options
    }
}
