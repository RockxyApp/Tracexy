import Foundation

// MARK: - CaptureFilterValidation

/// What libpcap says about a capture-filter expression, before any capture starts.
nonisolated enum CaptureFilterValidation: Equatable, Sendable {
    /// Nothing to check: the expression is blank, so every packet is captured.
    case empty
    /// libpcap compiled it; `instructionCount` is the size of the BPF program.
    case valid(instructionCount: Int)
    /// libpcap refused it; `message` is libpcap's own reason.
    case invalid(message: String)
    /// libpcap could not be loaded here, so the expression was not checked. The
    /// capture start still compiles it and reports any error then.
    case unavailable
}

// MARK: - CaptureFilterValidator

/// Compiles a BPF expression against a *dead* libpcap handle — no interface is
/// opened and no privilege is needed — so the Capture settings can say whether a
/// filter is valid while it is typed. It uses the same `pcap_compile` (optimized,
/// netmask unknown) the capture start uses, so a filter accepted here is accepted
/// there for the same link type.
nonisolated enum CaptureFilterValidator {
    // MARK: Internal

    /// Ethernet: the link type of almost every Mac interface a filter is written for.
    static let defaultLinkType: Int32 = 1
    static let snapLength: Int32 = 65_535
    /// The longest expression checked; libpcap itself has no need for more.
    static let maximumExpressionUTF8Bytes = 4_096

    static func validate(_ expression: String, linkType: Int32 = defaultLinkType) -> CaptureFilterValidation {
        let trimmed = expression.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return .empty
        }
        guard trimmed.utf8.count <= maximumExpressionUTF8Bytes else {
            return .invalid(message: "The expression is longer than \(maximumExpressionUTF8Bytes) bytes.")
        }
        guard let functions = Functions.shared else {
            return .unavailable
        }
        guard let handle = functions.openDead(linkType, snapLength) else {
            return .unavailable
        }
        defer { functions.close(handle) }

        // `struct bpf_program { u_int bf_len; struct bpf_insn *bf_insns; }` — 16
        // bytes on LP64, zeroed so a failed compile leaves nothing to free.
        let program = UnsafeMutableRawPointer.allocate(byteCount: 16, alignment: 8)
        program.initializeMemory(as: UInt8.self, repeating: 0, count: 16)
        defer { program.deallocate() }
        let result = trimmed.withCString { functions.compile(handle, program, $0, 1, 0xFFFFFFFF) }
        guard result == 0 else {
            let message = functions.error(handle).map { String(cString: $0) } ?? ""
            return .invalid(message: message.isEmpty ? "libpcap could not compile this expression." : message)
        }
        let count = Int(program.load(as: UInt32.self))
        functions.free(program)
        return .valid(instructionCount: count)
    }

    // MARK: Private

    /// The libpcap entry points, resolved once. `pcap_open_dead` needs no device.
    private struct Functions: @unchecked Sendable {
        typealias OpenDead = @convention(c) (Int32, Int32) -> OpaquePointer?
        typealias Close = @convention(c) (OpaquePointer?) -> Void
        typealias Compile = @convention(c) (
            OpaquePointer?, UnsafeMutableRawPointer?, UnsafePointer<CChar>?, Int32, UInt32
        )
            -> Int32
        typealias FreeCode = @convention(c) (UnsafeMutableRawPointer?) -> Void
        typealias GetError = @convention(c) (OpaquePointer?) -> UnsafePointer<CChar>?

        static let shared: Functions? = {
            guard let library = dlopen("/usr/lib/libpcap.A.dylib", RTLD_NOW) ?? dlopen("libpcap.A.dylib", RTLD_NOW),
                  let openDead = dlsym(library, "pcap_open_dead"),
                  let close = dlsym(library, "pcap_close"),
                  let compile = dlsym(library, "pcap_compile"),
                  let freeCode = dlsym(library, "pcap_freecode"),
                  let getError = dlsym(library, "pcap_geterr") else
            {
                return nil
            }
            return Functions(
                openDead: unsafeBitCast(openDead, to: OpenDead.self),
                close: unsafeBitCast(close, to: Close.self),
                compile: unsafeBitCast(compile, to: Compile.self),
                free: unsafeBitCast(freeCode, to: FreeCode.self),
                error: unsafeBitCast(getError, to: GetError.self)
            )
        }()

        let openDead: OpenDead
        let close: Close
        let compile: Compile
        let free: FreeCode
        let error: GetError
    }
}

// MARK: - SavedCaptureFilter

/// A named capture filter kept in the Project, so a filter written once can be
/// chosen again instead of retyped.
nonisolated struct SavedCaptureFilter: Hashable, Codable, Sendable, Identifiable {
    static let maximumCount = 30
    static let maximumNameCharacters = 60

    let id: UUID
    var name: String
    var expression: String

    /// `filters` with `expression` saved under `name`: a name that exists (ignoring
    /// case) is replaced in place; a new one is appended while there is room.
    /// Returns `nil` when the name or expression is blank or the list is full.
    static func saving(
        _ expression: String,
        named name: String,
        into filters: [SavedCaptureFilter]
    )
        -> [SavedCaptureFilter]?
    {
        let trimmedName = String(name.trimmingCharacters(in: .whitespacesAndNewlines).prefix(maximumNameCharacters))
        let trimmedExpression = expression.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty, !trimmedExpression.isEmpty else {
            return nil
        }
        var updated = filters
        if let index = updated.firstIndex(where: { $0.name.caseInsensitiveCompare(trimmedName) == .orderedSame }) {
            updated[index].expression = trimmedExpression
            return updated
        }
        guard updated.count < maximumCount else {
            return nil
        }
        updated.append(SavedCaptureFilter(id: UUID(), name: trimmedName, expression: trimmedExpression))
        return updated
    }

    static func decode(_ data: Data) -> [SavedCaptureFilter] {
        (try? JSONDecoder().decode([SavedCaptureFilter].self, from: data)).map { Array($0.prefix(maximumCount)) }
            ?? []
    }

    static func encode(_ filters: [SavedCaptureFilter]) -> Data {
        (try? JSONEncoder().encode(filters)) ?? Data("[]".utf8)
    }
}
