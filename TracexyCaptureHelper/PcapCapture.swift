import Foundation

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
    }

    // MARK: Internal

    struct Failure: Error { let message: String }

    struct PcapPacketHeader {
        var ts: timeval
        var caplen: UInt32
        var len: UInt32
    }

    func start(
        interface: String,
        onBatch: @escaping @Sendable ([Data], UInt32) -> Void,
        onError: @escaping @Sendable (String) -> Void
    ) {
        stop()
        var errbuf = [CChar](repeating: 0, count: 256)
        let handle = interface.withCString { name in openLive(name, 65_536, 1, 100, &errbuf) }
        guard let handle else {
            onError(String(cString: errbuf))
            return
        }
        self.handle = handle
        let linkType = UInt32(bitPattern: dataLink(handle))
        running = true
        let worker = Thread { [weak self] in self?.loop(handle: handle, linkType: linkType, onBatch: onBatch) }
        worker.name = "com.amunx.tracexy.helper.capture"
        worker.stackSize = 1 << 20
        thread = worker
        worker.start()
    }

    func stop() {
        running = false
        if let handle {
            closeHandle(handle)
            self.handle = nil
        }
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

    private let library: UnsafeMutableRawPointer
    private let openLive: OpenLiveFn
    private let nextEx: NextExFn
    private let closeHandle: CloseFn
    private let dataLink: DataLinkFn

    private var handle: OpaquePointer?
    private var thread: Thread?
    private var running = false

    private static func symbol<T>(_ library: UnsafeMutableRawPointer, _ name: String, as _: T.Type) throws -> T {
        guard let pointer = dlsym(library, name) else {
            throw Failure(message: "missing symbol \(name)")
        }
        return unsafeBitCast(pointer, to: T.self)
    }

    private func loop(handle: OpaquePointer, linkType: UInt32, onBatch: @escaping @Sendable ([Data], UInt32) -> Void) {
        var batch: [Data] = []
        var lastFlush = Date()
        while running {
            var headerRaw: UnsafeMutableRawPointer?
            var dataPointer: UnsafePointer<UInt8>?
            let result = nextEx(handle, &headerRaw, &dataPointer)
            if result == 1, let headerRaw, let data = dataPointer {
                let header = headerRaw.assumingMemoryBound(to: PcapPacketHeader.self).pointee
                batch.append(Data(bytes: data, count: Int(header.caplen)))
            } else if result < 0 {
                break
            }
            if !batch.isEmpty, Date().timeIntervalSince(lastFlush) > 0.25 {
                onBatch(batch, linkType)
                batch.removeAll(keepingCapacity: true)
                lastFlush = Date()
            }
        }
        if !batch.isEmpty {
            onBatch(batch, linkType)
        }
    }
}
