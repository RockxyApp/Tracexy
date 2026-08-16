import Foundation

/// libpcap-backed live capture for the privileged helper.
///
/// Teardown is race-free via ``CaptureWorkerLifecycle``: the caller requests stop
/// and waits, and only the worker thread reads stats, does the final flush, and
/// closes the pcap handle before signaling. Closing the handle from the caller's
/// thread while `pcap_next_ex` is mid-read frees it under the reader and crashes
/// (`EXC_BAD_ACCESS` in `pcap_read_bpf`) — so the close lives on the worker.
final class PcapCapture: @unchecked Sendable {
    // MARK: Lifecycle

    init() throws {
        guard let library = dlopen("/usr/lib/libpcap.A.dylib", RTLD_NOW) ?? dlopen("libpcap.A.dylib", RTLD_NOW) else {
            throw Failure(message: "libpcap not available")
        }
        self.library = library
        openLive = try PcapCapture.symbol(library, "pcap_open_live", as: OpenLiveFn.self)
        nextEx = try PcapCapture.symbol(library, "pcap_next_ex", as: NextExFn.self)
        closeHandle = try PcapCapture.symbol(library, "pcap_close", as: CloseFn.self)
        dataLink = try PcapCapture.symbol(library, "pcap_datalink", as: DataLinkFn.self)
        // Optional: `pcap_stats` is unsupported on some sources, so a missing
        // symbol must not fail the capture — the app is then told accounting is
        // unavailable rather than shown a fabricated clean figure.
        stats = try? PcapCapture.symbol(library, "pcap_stats", as: StatsFn.self)
        // Optional: only needed when a BPF filter is configured. Resolved lazily so
        // a plain (no-filter) capture never fails on a missing symbol; a requested
        // filter with these unavailable fails the start with a clear message.
        compileFilter = try? PcapCapture.symbol(library, "pcap_compile", as: CompileFn.self)
        setFilter = try? PcapCapture.symbol(library, "pcap_setfilter", as: SetFilterFn.self)
        freeCode = try? PcapCapture.symbol(library, "pcap_freecode", as: FreeCodeFn.self)
        getError = try? PcapCapture.symbol(library, "pcap_geterr", as: GetErrFn.self)
    }

    // MARK: Internal

    struct Failure: Error { let message: String }

    /// pcap_pkthdr — must match the C layout: { struct timeval ts; u32 caplen; u32 len }.
    struct PcapPacketHeader {
        var ts: timeval
        var caplen: UInt32
        var len: UInt32
    }

    /// Start capturing on `interface`.
    ///
    /// - `onBatch` delivers typed frames, each carrying its own libpcap timestamp,
    ///   captured length, original on-wire length, and link type.
    /// - `onStatistics` delivers a `pcap_stats` sample, or `nil` when accounting
    ///   is unavailable — never a silent gap the UI would read as "no loss".
    ///
    /// Opening the handle happens synchronously: on failure this throws (so the
    /// caller never reports a started capture that isn't running), and on success
    /// it returns the interface's real link type (DLT) *before* the worker starts,
    /// so the caller can report an authoritative link type even before the first
    /// frame arrives.
    @discardableResult
    func start(
        configuration: CaptureConfiguration,
        onBatch: @escaping @Sendable ([CapturedFrameMessage]) -> Void,
        onStatistics: @escaping @Sendable (HelperCaptureStats?) -> Void
    )
        throws -> UInt32
    {
        lifecycle.stop()
        // Re-validate on the privileged side even though the app validated too:
        // bounds must hold regardless of what crossed the wire (defense in depth).
        let config: CaptureConfiguration
        switch configuration.validated() {
        case let .success(normalized):
            config = normalized
        case let .failure(error):
            throw Failure(message: error.message)
        }
        var errbuf = [CChar](repeating: 0, count: 256)
        let snaplen = Int32(config.snapLength)
        let promisc: Int32 = config.promiscuous ? 1 : 0
        let handle = config.interface.withCString { name in openLive(name, snaplen, promisc, 100, &errbuf) }
        guard let handle else {
            throw Failure(message: String(cString: errbuf))
        }
        // Compile + install any BPF filter before reporting the capture started.
        // A bad expression fails closed here (handle closed, program freed) so the
        // caller never reports a running capture that silently ignored the filter.
        if let expression = config.bpf {
            do {
                try applyFilter(expression, handle: handle)
            } catch {
                closeHandle(handle)
                throw error
            }
        }
        let linkType = UInt32(bitPattern: dataLink(handle))
        // The raw C handle and close fn are not `Sendable`; carry them across the
        // worker boundary in a narrow `@unchecked Sendable` box rather than
        // suppressing concurrency checking. The handle is only ever touched on the
        // worker thread that owns the read loop.
        let owned = OwnedHandle(handle: handle, close: closeHandle)
        lifecycle.start(name: "com.amunx.tracexy.helper.capture") { [weak self] isRunning in
            self?.loop(
                handle: owned.handle, linkType: linkType, isRunning: isRunning,
                onBatch: onBatch, onStatistics: onStatistics
            )
            // Close on the SAME thread that read from it, and only after the loop
            // has fully exited. See the type comment.
            owned.close(owned.handle)
        }
        return linkType
    }

    /// Requests stop and blocks until the worker has flushed, closed its handle,
    /// and exited. Idempotent.
    func stop() {
        lifecycle.stop()
    }

    // MARK: Private

    /// Narrow `@unchecked Sendable` owner for the raw pcap handle and its close
    /// function, so the worker closure can carry them across the concurrency
    /// boundary without globally suppressing checking. Safe because the handle is
    /// only ever dereferenced (and closed) on the single worker thread.
    private struct OwnedHandle: @unchecked Sendable {
        let handle: OpaquePointer
        let close: CloseFn
    }

    private typealias OpenLiveFn = @convention(c) (
        UnsafePointer<CChar>?,
        Int32,
        Int32,
        Int32,
        UnsafeMutablePointer<CChar>?
    )
        -> OpaquePointer?
    private typealias NextExFn = @convention(c) (
        OpaquePointer?,
        UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
        UnsafeMutablePointer<UnsafePointer<UInt8>?>?
    )
        -> Int32
    private typealias CloseFn = @convention(c) (OpaquePointer?) -> Void
    private typealias DataLinkFn = @convention(c) (OpaquePointer?) -> Int32
    private typealias StatsFn = @convention(c) (OpaquePointer?, UnsafeMutableRawPointer?) -> Int32
    /// `int pcap_compile(pcap_t*, struct bpf_program*, const char*, int optimize, bpf_u_int32 netmask)`.
    private typealias CompileFn = @convention(c) (
        OpaquePointer?, UnsafeMutableRawPointer?, UnsafePointer<CChar>?, Int32, UInt32
    )
        -> Int32
    /// `int pcap_setfilter(pcap_t*, struct bpf_program*)`.
    private typealias SetFilterFn = @convention(c) (OpaquePointer?, UnsafeMutableRawPointer?) -> Int32
    /// `void pcap_freecode(struct bpf_program*)`.
    private typealias FreeCodeFn = @convention(c) (UnsafeMutableRawPointer?) -> Void
    /// `char *pcap_geterr(pcap_t*)`.
    private typealias GetErrFn = @convention(c) (OpaquePointer?) -> UnsafePointer<CChar>?

    private let library: UnsafeMutableRawPointer
    private let openLive: OpenLiveFn
    private let nextEx: NextExFn
    private let closeHandle: CloseFn
    private let dataLink: DataLinkFn
    private let stats: StatsFn?
    private let compileFilter: CompileFn?
    private let setFilter: SetFilterFn?
    private let freeCode: FreeCodeFn?
    private let getError: GetErrFn?

    private let lifecycle = CaptureWorkerLifecycle()

    private static func symbol<T>(_ library: UnsafeMutableRawPointer, _ name: String, as _: T.Type) throws -> T {
        guard let pointer = dlsym(library, name) else {
            throw Failure(message: "missing symbol \(name)")
        }
        return unsafeBitCast(pointer, to: T.self)
    }

    /// Compile and install a BPF filter on an open handle, freeing the compiled
    /// program on every path. Throws with libpcap's own error text (via
    /// `pcap_geterr`) so a bad expression surfaces the real reason.
    private func applyFilter(_ expression: String, handle: OpaquePointer) throws {
        guard let compileFilter, let setFilter, let freeCode else {
            throw Failure(message: "BPF filtering is unavailable on this system.")
        }
        // `struct bpf_program { u_int bf_len; struct bpf_insn *bf_insns; }` is 16
        // bytes on LP64. Zero it so a failed compile leaves nothing to free.
        let programSize = 16
        let program = UnsafeMutableRawPointer.allocate(byteCount: programSize, alignment: 8)
        program.initializeMemory(as: UInt8.self, repeating: 0, count: programSize)
        defer { program.deallocate() }
        let netmaskUnknown: UInt32 = 0xFFFFFFFF
        let compiled = expression.withCString { cstr in
            compileFilter(handle, program, cstr, 1, netmaskUnknown)
        }
        guard compiled == 0 else {
            throw Failure(message: filterErrorMessage(handle: handle, fallback: "invalid BPF filter expression."))
        }
        // Once compiled, free the program regardless of how setfilter goes — the
        // kernel/handle keeps its own copy after a successful install.
        defer { freeCode(program) }
        guard setFilter(handle, program) == 0 else {
            throw Failure(message: filterErrorMessage(handle: handle, fallback: "could not apply the BPF filter."))
        }
    }

    private func filterErrorMessage(handle: OpaquePointer, fallback: String) -> String {
        if let getError, let cstr = getError(handle) {
            let message = String(cString: cstr)
            if !message.isEmpty {
                return message
            }
        }
        return fallback
    }

    /// Sampled by the worker thread itself. `pcap_stats` needs the same handle the
    /// read loop owns, and that handle is closed on this thread when the loop
    /// exits — reading it from anywhere else would race that teardown.
    private func sampleStatistics(handle: OpaquePointer) -> HelperCaptureStats? {
        guard let stats else {
            return nil
        }
        // `struct pcap_stat` is { u_int ps_recv; u_int ps_drop; u_int ps_ifdrop }
        // on this platform, but some builds append further fields. A Swift struct
        // isn't representable across `@convention(c)`, so read raw memory and
        // over-allocate: writing past three slots stays inside our buffer.
        let slotCount = 8
        let buffer = UnsafeMutableRawPointer.allocate(
            byteCount: MemoryLayout<UInt32>.stride * slotCount,
            alignment: MemoryLayout<UInt32>.alignment
        )
        defer { buffer.deallocate() }
        buffer.initializeMemory(as: UInt32.self, repeating: 0, count: slotCount)
        guard stats(handle, buffer) == 0 else {
            return nil
        }
        let fields = buffer.assumingMemoryBound(to: UInt32.self)
        return HelperCaptureStats(
            received: fields[0],
            droppedByKernel: fields[1],
            droppedByInterface: fields[2]
        )
    }

    private func loop(
        handle: OpaquePointer,
        linkType: UInt32,
        isRunning: () -> Bool,
        onBatch: @escaping @Sendable ([CapturedFrameMessage]) -> Void,
        onStatistics: @escaping @Sendable (HelperCaptureStats?) -> Void
    ) {
        var batch: [CapturedFrameMessage] = []
        var lastFlush = Date()
        while isRunning() {
            var headerRaw: UnsafeMutableRawPointer?
            var dataPointer: UnsafePointer<UInt8>?
            let result = nextEx(handle, &headerRaw, &dataPointer)
            if result == 1, let headerRaw, let data = dataPointer {
                let header = headerRaw.assumingMemoryBound(to: PcapPacketHeader.self).pointee
                let captured = Int(header.caplen)
                batch.append(CapturedFrameMessage(
                    bytes: Data(bytes: data, count: captured),
                    timestampSeconds: Int64(header.ts.tv_sec),
                    timestampMicroseconds: Int64(header.ts.tv_usec),
                    capturedLength: Int64(header.caplen),
                    originalLength: Int64(header.len),
                    linkType: linkType
                ))
            } else if result < 0 {
                break
            }
            if !batch.isEmpty, Date().timeIntervalSince(lastFlush) > 0.25 {
                onBatch(batch)
                batch.removeAll(keepingCapacity: true)
                lastFlush = Date()
                // Once per flush, not per packet: a syscall that only has to be as
                // fresh as the numbers it qualifies.
                onStatistics(sampleStatistics(handle: handle))
            }
        }
        if !batch.isEmpty {
            onBatch(batch)
        }
        // Final reading, so a short capture still reports its loss.
        onStatistics(sampleStatistics(handle: handle))
    }
}
