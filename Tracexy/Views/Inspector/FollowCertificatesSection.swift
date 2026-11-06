import AppKit
import SwiftUI
import UniformTypeIdentifiers

// MARK: - FollowCertificatesSection

/// Certificates each direction sent in the clear, read from the follow result's
/// leading bytes under ``TLSCertificateExtraction``'s policy. Hidden entirely for a
/// stream that is not TLS.
struct FollowCertificatesSection: View {
    // MARK: Internal

    let result: FollowStreamResult

    var body: some View {
        // Derived per render rather than in a `.task`: an empty body is never
        // rendered, so a task on it would never run. The walk is cheap — it stops
        // at the first Certificate message, ChangeCipherSpec or non-TLS byte.
        content(CertificatePair(
            aToB: TLSCertificateExtraction.extract(from: result.aToB),
            bToA: TLSCertificateExtraction.extract(from: result.bToA)
        ))
    }

    // MARK: Private

    private struct CertificatePair: Equatable {
        let aToB: TLSCertificateExtraction
        let bToA: TLSCertificateExtraction
    }

    private static let pemType = UTType(filenameExtension: "pem") ?? .data

    @State private var exportError: String?

    @ViewBuilder
    private func content(_ pair: CertificatePair) -> some View {
        let senders: [(String, TLSCertificateExtraction)] = [
            (result.tuple.b.display, pair.bToA),
            (result.tuple.a.display, pair.aToB),
        ]
        let withCertificates = senders.filter { !$0.1.certificates.isEmpty }
        if !withCertificates.isEmpty {
            ForEach(withCertificates, id: \.0) { sender, extraction in
                chain(sender: sender, extraction: extraction)
            }
            if let exportError {
                Label(exportError, systemImage: "exclamationmark.triangle")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }
        } else if let explanation = tlsAbsence(senders.map(\.1)) {
            HStack(spacing: Theme.Metrics.spacingS) {
                Image(systemName: "lock.doc")
                    .foregroundStyle(.secondary)
                Text(explanation)
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func chain(sender: String, extraction: TLSCertificateExtraction) -> some View {
        let certificates = extraction.certificates
        return GroupBox {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(certificates.enumerated()), id: \.offset) { index, certificate in
                    certificateRow(certificate)
                    if index < certificates.count - 1 {
                        Divider()
                    }
                }
                if case let .certificates(_, unparsed, omitted) = extraction, unparsed + omitted > 0 {
                    Text("\((unparsed + omitted).formatted()) more entries could not be listed")
                        .font(Theme.Typography.caption)
                        .foregroundStyle(.secondary)
                        .padding(.top, Theme.Metrics.spacingS)
                }
            }
        } label: {
            HStack {
                Text("Certificates sent by \(sender)")
                    .font(Theme.Typography.captionMedium)
                Spacer()
                if certificates.count > 1 {
                    Button("Save Chain…") {
                        save(
                            Data(certificates.map(\.pem).joined().utf8),
                            name: "\(fileStem(certificates[0]))-chain.pem",
                            type: Self.pemType
                        )
                    }
                    .controlSize(.small)
                    .help("Save every certificate in the order sent, as PEM")
                }
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Certificates sent by \(sender)")
    }

    private func certificateRow(_ certificate: X509CertificateSummary) -> some View {
        HStack(alignment: .top, spacing: Theme.Metrics.spacingM) {
            Image(systemName: "doc.text")
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(certificate.displayName)
                    .font(Theme.Typography.bodyEmphasis)
                    .textSelection(.enabled)
                Text(certificate.isSelfIssued
                    ? "Issued by itself"
                    : "Issued by \(certificate.issuer.commonName ?? certificate.issuer.displayString)")
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
                    .help(certificate.issuer.displayString)
                Text(validity(certificate))
                    .font(Theme.Typography.caption)
                    .foregroundStyle(.secondary)
                if !certificate.subjectAlternativeNames.isEmpty {
                    Text(certificate.subjectAlternativeNames.joined(separator: ", "))
                        .font(Theme.Typography.monoSmall)
                        .lineLimit(2)
                        .textSelection(.enabled)
                        .help("Subject alternative names")
                }
            }
            Spacer(minLength: Theme.Metrics.spacingM)
            Menu {
                Button("Save as DER…") {
                    save(Data(certificate.der), name: "\(fileStem(certificate)).cer", type: .x509Certificate)
                }
                Button("Save as PEM…") {
                    save(Data(certificate.pem.utf8), name: "\(fileStem(certificate)).pem", type: Self.pemType)
                }
                Divider()
                Button("Copy PEM") {
                    copy(certificate.pem, subject: String(localized: "PEM"))
                }
                Button("Copy SHA-256 Fingerprint") {
                    copy(certificate.fingerprintHex, subject: String(localized: "SHA-256 fingerprint"))
                }
            } label: {
                Image(systemName: "square.and.arrow.up")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .accessibilityLabel("Export \(certificate.displayName)")
            .help("Save or copy this certificate exactly as it was sent")
        }
        .padding(.vertical, 6)
        .help("SHA-256 \(certificate.fingerprintHex)")
    }

    /// The one explanation worth showing when neither direction listed a
    /// certificate — only for a stream that actually carried TLS records.
    private func tlsAbsence(_ outcomes: [TLSCertificateExtraction]) -> String? {
        for outcome in outcomes {
            switch outcome {
            case .encryptedBeforeCertificate,
                 .certificates:
                return outcome.absenceExplanation
            default:
                continue
            }
        }
        return nil
    }

    private func validity(_ certificate: X509CertificateSummary) -> String {
        let style = Date.FormatStyle(date: .abbreviated, time: .omitted, timeZone: .gmt)
        return "Valid \(certificate.notBefore.formatted(style)) to \(certificate.notAfter.formatted(style))"
    }

    private func fileStem(_ certificate: X509CertificateSummary) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_."))
        let stem = String(certificate.displayName.unicodeScalars.map { allowed.contains($0) ? Character($0) : "-" })
        return stem.isEmpty ? "certificate" : stem
    }

    /// Copies one certificate field, reporting the pasteboard's own refusal rather
    /// than letting a failed copy look like a successful one.
    private func copy(_ text: String, subject: String) {
        NSPasteboard.general.clearContents()
        if NSPasteboard.general.setString(text, forType: .string) {
            exportError = nil
        } else {
            exportError = String(localized: "The \(subject) could not be copied to the clipboard.")
        }
    }

    private func save(_ data: Data, name: String, type: UTType) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [type]
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = name
        panel.message = "Saves the certificate exactly as it was sent. It contains no private key."
        guard panel.runModal() == .OK, let url = panel.url else {
            return
        }
        do {
            try data.write(to: url, options: .atomic)
            exportError = nil
        } catch {
            exportError = "The certificate could not be saved: \(error.localizedDescription)"
        }
    }
}
