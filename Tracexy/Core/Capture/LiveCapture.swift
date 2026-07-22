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
    }

    // MARK: Internal

    struct Failure: Error { let message: String }

    /// pcap_pkthdr — must match the C layout: { struct timeval ts; u32 caplen; u32 len }.
    struct PcapPacketHeader {
        var ts: timeval
        var caplen: UInt32
        var len: UInt32
    }

    /// Start capturing on `interface`. `onBatch` and `onError` fire on a
    /// background thread; the caller hops to the main actor.
    func start(
        interface: String,
        onBatch: @escaping @Sendable ([CapturedFrame], UInt32) -> Void,
        onError: @escaping @Sendable (String) -> Void,
        onStatistics: (@Sendable (CaptureStatistics) -> Void)? = nil
    ) {
        stop()
        var errbuf = [CChar](repeating: 0, count: 256)
        let handle = interface.withCString { name in
            openLive(name, 65_536, 1, 100, &errbuf)
        }
        guard let handle else {
            onError(String(cString: errbuf))
            return
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

    private let library: UnsafeMutableRawPointer
    private let openLive: OpenLiveFn
    private let nextEx: NextExFn
    private let closeHandle: CloseFn
    private let dataLink: DataLinkFn
    private let stats: StatsFn?

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
