import Foundation

// MARK: - CapturePreview

/// What the Open panel (and the Quick Look extension) can say about a file
/// before it is opened: its format, size, how many records a bounded scan saw,
/// and the first timestamp plus elapsed span. Mirrors the distinctions
/// Wireshark's open-dialog preview makes — a scan that hit its budget says so
/// rather than pretending to know the total.
nonisolated struct CapturePreview: Sendable, Equatable {
    nonisolated enum Status: Sendable, Equatable {
        /// Every record was scanned.
        case complete
        /// The record or time budget ran out; `records` is a lower bound.
        case timedOut
        /// A read error occurred after `records` records.
        case errorAfterRecords
        case unknownFormat
        case compressed(String)
        case directory
        case unreadable
    }

    let status: Status
    let formatDescription: String
    let fileSize: UInt64
    let records: Int
    let firstTimestamp: Date?
    let lastTimestamp: Date?

    var elapsed: TimeInterval? {
        guard status == .complete, let firstTimestamp, let lastTimestamp else {
            return nil
        }
        return lastTimestamp.timeIntervalSince(firstTimestamp)
    }
}

// MARK: - CapturePreviewScanner

/// A budgeted, cancellable scan of a capture's leading records. Runs on the
/// caller's executor (never `@MainActor`) and stops at whichever comes first:
/// the record cap, the wall-clock budget, cancellation, or the end of the file.
nonisolated enum CapturePreviewScanner {
    nonisolated struct Budget: Sendable {
        var maxRecords = 100_000
        var maxDuration: Duration = .milliseconds(250)
    }

    static func scan(
        _ url: URL,
        budget: Budget = Budget(),
        isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled }
    )
        -> CapturePreview
    {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory) else {
            return CapturePreview(
                status: .unreadable, formatDescription: "", fileSize: 0, records: 0,
                firstTimestamp: nil, lastTimestamp: nil
            )
        }
        if isDirectory.boolValue {
            return CapturePreview(
                status: .directory, formatDescription: String(localized: "Folder"), fileSize: 0, records: 0,
                firstTimestamp: nil, lastTimestamp: nil
            )
        }
        let size = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?
            .uint64Value ?? 0

        let format: CaptureContentFormat
        do {
            format = try CaptureImporter.recognizedFormat(of: url)
        } catch let error as CaptureImportError {
            switch error {
            case let .compressed(container):
                return CapturePreview(
                    status: .compressed(container), formatDescription: String(localized: "\(container) archive"),
                    fileSize: size, records: 0, firstTimestamp: nil, lastTimestamp: nil
                )
            case .sourceIsDirectory:
                return CapturePreview(
                    status: .directory, formatDescription: String(localized: "Folder"), fileSize: size, records: 0,
                    firstTimestamp: nil, lastTimestamp: nil
                )
            default:
                return CapturePreview(
                    status: .unknownFormat, formatDescription: String(localized: "Unknown format"),
                    fileSize: size, records: 0, firstTimestamp: nil, lastTimestamp: nil
                )
            }
        } catch {
            return CapturePreview(
                status: .unreadable, formatDescription: "", fileSize: size, records: 0,
                firstTimestamp: nil, lastTimestamp: nil
            )
        }

        let description = switch format {
        case .pcap: String(localized: "PCAP (libpcap)")
        case .pcapng: String(localized: "PCAPNG")
        }

        guard let reader = try? CaptureStreamReader(
            contentsOf: url, configuration: .init(isCancelled: isCancelled)
        ) else {
            return CapturePreview(
                status: .errorAfterRecords, formatDescription: description, fileSize: size, records: 0,
                firstTimestamp: nil, lastTimestamp: nil
            )
        }

        let clock = ContinuousClock()
        let deadline = clock.now + budget.maxDuration
        var records = 0
        var first: Date?
        var last: Date?
        var status = CapturePreview.Status.complete
        scanning: while true {
            if records >= budget.maxRecords || clock.now >= deadline {
                status = .timedOut
                break
            }
            do {
                switch try reader.next() {
                case let .frame(event):
                    records += 1
                    if let timestamp = event.reference.timestamp {
                        first = first.map { min($0, timestamp) } ?? timestamp
                        last = last.map { max($0, timestamp) } ?? timestamp
                    }
                case .end:
                    break scanning
                }
            } catch is CancellationError {
                status = .timedOut
                break
            } catch {
                status = .errorAfterRecords
                break
            }
        }
        return CapturePreview(
            status: status,
            formatDescription: description,
            fileSize: size,
            records: records,
            firstTimestamp: first,
            lastTimestamp: last
        )
    }
}
