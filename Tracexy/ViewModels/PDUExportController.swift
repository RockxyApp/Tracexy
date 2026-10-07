import AppKit
import Foundation
import Observation
import UniformTypeIdentifiers

// MARK: - PDUExportController

/// File ▸ Export PDUs…: the application payloads of the sessions in view, written as
/// a PCAPNG of Wireshark Upper PDUs (see ``PDUExporter``). On the same terms as
/// Export Frames: a saved capture or a stopped live capture, the raw-export privacy
/// acknowledgement, and an outcome reported where capture I/O outcomes go.
@MainActor
@Observable
final class PDUExportController {
    // MARK: Internal

    static let shared = PDUExportController()

    private(set) var isExporting = false

    func export(from coordinator: MainContentCoordinator) {
        guard !isExporting else {
            return
        }
        guard coordinator.canExportFrames else {
            coordinator.captureError = coordinator.captureSourceHoldMessage
                ?? String(localized: "Open a saved capture or stop the live capture before exporting PDUs.")
            return
        }
        let privacy = PrivacySettingsResolver.exportPolicy(defaults: coordinator.activeProjectDefaults)
        if privacy.hasProtections, !coordinator.presentRawExportAcknowledgement(formatName: "PCAPNG") {
            return
        }
        let panel = NSSavePanel()
        panel.title = String(localized: "Export PDUs")
        panel
            .message =
            String(localized: "Each recognized message of the sessions in view, for Wireshark to dissect directly.")
        panel.allowedContentTypes = [UTType(filenameExtension: "pcapng") ?? .data]
        panel.nameFieldStringValue = "PDUs.pcapng"
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let output = panel.url else {
            return
        }
        let originProjectID = coordinator.activeRuntime.projectID
        let originGeneration = coordinator.startGeneration
        let sessions = coordinator.visibleSessions
        let tuples = Dictionary(
            coordinator.connectionSnapshot.summaries.map { (SessionBuilder.sessionID(for: $0.tuple), $0.tuple) },
            uniquingKeysWith: { first, _ in first }
        )
        let streams = sessions.compactMap { session -> PDUExporter.Stream? in
            guard let tuple = tuples[session.id], tuple.proto == .tcp,
                  let kind = session.protocolStack.last(where: { PDUExporter.dissectorName($0, tcp: true) != nil }) else
            {
                return nil
            }
            return PDUExporter.Stream(tuple: tuple, kind: kind)
        }
        let datagrams = Set(sessions.filter { $0.protocolStack.contains(.udp) }.map(\.id))
        let savedURL = coordinator.isViewingSavedCapture ? coordinator.savedCaptureEvidenceURL : nil
        let savedIdentity = coordinator.adoptedSavedCaptureIdentity
        let spool = coordinator.liveCaptureSpool
        isExporting = true
        Task { [weak coordinator] in
            var failure: String?
            var warning: String?
            var didWrite = false
            do {
                let summary = try await Task.detached(priority: .userInitiated) { () throws -> PDUExportSummary in
                    if let savedURL, let savedIdentity {
                        return try PDUExporter.export(
                            from: savedURL, expectedIdentity: savedIdentity, streams: streams,
                            datagramSessions: datagrams, to: output
                        )
                    }
                    let copy = FileManager.default.temporaryDirectory
                        .appendingPathComponent("tracexy-pdu-\(UUID().uuidString).pcapng")
                    defer { try? FileManager.default.removeItem(at: copy) }
                    try await spool.copyWholeCapture(to: copy)
                    let handle = try FileHandle(forReadingFrom: copy)
                    let identity = PcapFileIdentity.snapshot(of: handle)
                    try handle.close()
                    return try PDUExporter.export(
                        from: copy, expectedIdentity: identity, streams: streams, datagramSessions: datagrams,
                        to: output
                    )
                }.value
                didWrite = true
                warning = Self.warning(summary)
            } catch is CancellationError {
                // Nothing was written: the exporter writes its file only at the end.
            } catch {
                failure = String(localized: "Couldn’t export PDUs: \(error.localizedDescription)")
            }
            isExporting = false
            coordinator?.reportCaptureIOOutcome(
                failure: failure, warning: warning, didWrite: didWrite,
                originProjectID: originProjectID, originGeneration: originGeneration
            )
        }
    }

    // MARK: Private

    private static func warning(_ summary: PDUExportSummary) -> String? {
        if summary.pduCount == 0 {
            return String(
                localized: "No recognized message was found in the sessions in view, so the PDU file is empty."
            )
        }
        if summary.skippedStreamCount > 0 || summary.omittedPDUCount > 0 {
            return String(localized: """
            Exported \(summary.pduCount.formatted()) PDUs; \(summary.skippedStreamCount.formatted()) streams and \
            \(summary.omittedPDUCount.formatted()) PDUs past the export limits were left out.
            """)
        }
        return nil
    }
}
