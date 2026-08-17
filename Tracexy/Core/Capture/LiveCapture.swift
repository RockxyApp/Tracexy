import Foundation

nonisolated final class LiveCapture: @unchecked Sendable {
    // MARK: Lifecycle

    init() throws {
        guard let library = dlopen("/usr/lib/libpcap.A.dylib", RTLD_NOW) ?? dlopen("libpcap.A.dylib", RTLD_NOW) else {
            throw Failure(message: "libpcap not available")
        }
        self.library = library
        openLive = try LiveCapture.symbol(library, "pcap_open_live", as: OpenLiveFn.self)
        nextEx = try LiveCapture.symbol(library, "pcap_next_ex", as: NextExFn.self)
        closeHandle = try LiveCapture.symbol(library, "pcap_close", as: CloseFn.self)
        dataLink = try LiveCapture.symbol(library, "pcap_datalink", as: DataLinkFn.self)
        // Optional: `pcap_stats` is unsupported on some sources (notably when
        // reading a savefile), so a missing symbol must not fail the capture.
        stats = try? LiveCapture.symbol(library, "pcap_stats", as: StatsFn.self)
        // Optional: only needed when a BPF filter is configured. A no-filter
        // capture never fails on these; a requested filter with them missing does.
        compileFilter = try? LiveCapture.symbol(library, "pcap_compile", as: CompileFn.self)
        setFilter = try? LiveCapture.symbol(library, "pcap_setfilter", as: SetFilterFn.self)
        freeCode = try? LiveCapture.symbol(library, "pcap_freecode", as: FreeCodeFn.self)
        getError = try? LiveCapture.symbol(library, "pcap_geterr", as: GetErrFn.self)
    }

    // MARK: Internal

    struct Failure: Error { let message: String }

    /// pcap_pkthdr — must match the C layout: { struct timeval ts; u32 caplen; u32 len }.
    struct PcapPacketHeader {
        var ts: timeval
        var caplen: UInt32
        var len: UInt32
    }

    /// Start capturing with a validated `configuration` (interface, snap length,
    /// promiscuous mode, optional BPF). `onBatch` fires on a background thread; the
    /// caller hops to the main actor.
    ///
    /// Opening the handle and compiling any BPF happen synchronously: this throws
    /// on an out-of-bounds value, an interface that can't be opened, or a bad
    /// filter, so the caller never reports a started capture that isn't running or
    /// silently dropped its filter. On success it returns the interface's real
    /// link type before the worker starts.
    @discardableResult
    func start(
        configuration: CaptureConfiguration,
        onBatch: @escaping @Sendable ([CapturedFrame], UInt32) -> Void,
        onStatistics: (@Sendable (CaptureStatistics) -> Void)? = nil
    )
        throws -> UInt32
    {
        stop()
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
        let handle = config.interface.withCString { name in
            openLive(name, snaplen, promisc, 100, &errbuf)
        }
        guard let handle else {
            throw Failure(message: String(cString: errbuf))
        }
        if let expression = config.bpf {
            do {
                try applyFilter(expression, handle: handle)
            } catch {
                closeHandle(handle)
                throw error
            }
        }
        self.handle = handle
        let linkType = UInt32(bitPattern: dataLink(handle))
        running = true
        let done = DispatchSemaphore(value: 0)
        finished = done
        let closeHandle = closeHandle
        let worker = Thread { [weak self] in
            self?.loop(handle: handle, linkType: linkType, onBatch: onBatch, onStatistics: onStatistics)
            // Close the handle on the SAME thread that read from it, and only
            // after the read loop has fully exited. Closing it from another
            // thread while `pcap_next_ex` is mid-read frees the handle under the
            // reader → `pcap_read_bpf` EXC_BAD_ACCESS. See `stop()`.
            closeHandle(handle)
            done.signal()
        }
        worker.name = "com.amunx.tracexy.capture"
        worker.stackSize = 1 << 20
        thread = worker
        worker.start()
        return linkType
    }

    /// Stops capture and blocks until the worker thread has left `pcap_next_ex`
    /// and closed its own handle. The capture handle uses a 100 ms read timeout,
    /// so the wait returns promptly. Idempotent.
    func stop() {
        guard running else {
            return
        }
        running = false
        // Wait for the worker to close the handle itself (never close it here —
        // that races the in-flight read and crashes).
        finished?.wait()
        finished = nil
        handle = nil
        thread = nil
    }

    // MARK: Private

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

    private var handle: OpaquePointer?
    private var thread: Thread?
    private var running = false
    /// Signaled by the worker thread once it has exited its read loop and closed
    /// the pcap handle; `stop()` waits on it so teardown is race-free.
    private var finished: DispatchSemaphore?

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

    /// Sampled by the worker thread itself. `pcap_stats` needs the same handle
    /// the read loop owns, and the handle is closed on this thread when the loop
    /// exits — reading it from anywhere else would race that teardown.
    private func sampleStatistics(handle: OpaquePointer) -> CaptureStatistics? {
        guard let stats else {
            return nil
        }
        // `struct pcap_stat` is { u_int ps_recv; u_int ps_drop; u_int ps_ifdrop }
        // on this platform, but some append further fields. A Swift struct is not
        // representable across `@convention(c)`, so read raw memory and
        // over-allocate: writing past three slots then stays inside our buffer.
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
        return CaptureStatistics(
            received: fields[0],
            droppedByKernel: fields[1],
            droppedByInterface: fields[2]
        )
    }

    private func loop(
        handle: OpaquePointer,
        linkType: UInt32,
        onBatch: @escaping @Sendable ([CapturedFrame], UInt32) -> Void,
        onStatistics: (@Sendable (CaptureStatistics) -> Void)?
    ) {
        var batch: [CapturedFrame] = []
        var lastFlush = Date()
        while running {
            var headerRaw: UnsafeMutableRawPointer?
            var dataPointer: UnsafePointer<UInt8>?
            let result = nextEx(handle, &headerRaw, &dataPointer)
            if result == 1, let headerRaw, let data = dataPointer {
                let header = headerRaw.assumingMemoryBound(to: PcapPacketHeader.self).pointee
                let captured = Int(header.caplen)
                let bytes = Array(UnsafeBufferPointer(start: data, count: captured))
                let timestamp =
                    Date(timeIntervalSince1970: Double(header.ts.tv_sec) + Double(header.ts.tv_usec) / 1_000_000)
                batch.append(CapturedFrame(bytes: bytes, timestamp: timestamp, originalLength: Int(header.len)))
            } else if result < 0 {
                break
            }
            if !batch.isEmpty, Date().timeIntervalSince(lastFlush) > 0.25 {
                onBatch(batch, linkType)
                batch.removeAll(keepingCapacity: true)
                lastFlush = Date()
                // Once per flush, not per packet: this is a syscall, and it only
                // has to be as fresh as the numbers it qualifies.
                if let onStatistics, let sample = sampleStatistics(handle: handle) {
                    onStatistics(sample)
                }
            }
        }
        if !batch.isEmpty {
            onBatch(batch, linkType)
        }
        // Final reading, so a short capture still reports its loss.
        if let onStatistics, let sample = sampleStatistics(handle: handle) {
            onStatistics(sample)
        }
    }
}
