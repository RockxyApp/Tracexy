import SwiftUI

extension AllFramesWindow {
    @ViewBuilder
    func decodeAsMenu(_ row: CaptureFrameRow) -> some View {
        let facts = row.filterFacts
        let projectID = coordinator.projectStore.activeProjectID
        let captureGeneration = coordinator.startGeneration
        let savedCaptureID = coordinator.activeSavedCapture?.id

        if facts?.sourceTCPPort != nil || facts?.destinationTCPPort != nil
            || facts?.sourceUDPPort != nil || facts?.destinationUDPPort != nil
        {
            Menu("Decode As…") {
                if let port = facts?.sourceTCPPort {
                    Button("TCP source port \(port)…") {
                        prepareDecodeAsDraft(
                            transport: .tcp, port: port, projectID: projectID,
                            captureGeneration: captureGeneration, savedCaptureID: savedCaptureID
                        )
                    }
                }
                if let port = facts?.destinationTCPPort {
                    Button("TCP destination port \(port)…") {
                        prepareDecodeAsDraft(
                            transport: .tcp, port: port, projectID: projectID,
                            captureGeneration: captureGeneration, savedCaptureID: savedCaptureID
                        )
                    }
                }
                if let port = facts?.sourceUDPPort {
                    Button("UDP source port \(port)…") {
                        prepareDecodeAsDraft(
                            transport: .udp, port: port, projectID: projectID,
                            captureGeneration: captureGeneration, savedCaptureID: savedCaptureID
                        )
                    }
                }
                if let port = facts?.destinationUDPPort {
                    Button("UDP destination port \(port)…") {
                        prepareDecodeAsDraft(
                            transport: .udp, port: port, projectID: projectID,
                            captureGeneration: captureGeneration, savedCaptureID: savedCaptureID
                        )
                    }
                }
            }
        }
    }

    private func prepareDecodeAsDraft(
        transport: DecodeAsRule.Transport,
        port: UInt16,
        projectID: UUID,
        captureGeneration: Int,
        savedCaptureID: URL?
    ) {
        guard coordinator.projectStore.activeProjectID == projectID,
              coordinator.startGeneration == captureGeneration,
              coordinator.activeSavedCapture?.id == savedCaptureID else
        {
            notice = String(localized: "The capture changed. Reopen its context menu to prepare Decode As.")
            return
        }
        coordinator.decodeAs.prepareRuleDraft(transport: transport, port: port)
        openWindow(id: TracexyApp.decodeAsWindowID)
    }
}
