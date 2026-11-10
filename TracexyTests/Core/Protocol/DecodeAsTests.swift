import Foundation
import Testing
@testable import Tracexy

/// Capture ▸ Decode As…: a port → protocol rule makes that port's payload decode as the
/// chosen protocol; without it the decoder keeps its own detection.
struct DecodeAsTests {
    // MARK: Internal

    @Test
    func aRuleMakesAnUnusualPortDecodeAsDNS() {
        let frame = PacketBuilder.ethernetIPv4(
            proto: 17, src: "192.0.2.10", dst: "198.51.100.53",
            payload: PacketBuilder.udp(
                srcPort: 50_000,
                dstPort: 5_300,
                payload: PacketBuilder.dnsQuery(name: "decode.example")
            )
        )
        let plain = decode(frame, rules: [])
        #expect(plain.appProtocol == nil)
        #expect(plain.dnsQuery == nil)

        let forced = decode(frame, rules: [DecodeAsRule(transport: .udp, port: 5_300, decode: .dns)])
        #expect(forced.appProtocol == .dns)
        #expect(forced.dnsQuery == "decode.example")

        let otherTransport = decode(frame, rules: [DecodeAsRule(transport: .tcp, port: 5_300, decode: .dns)])
        #expect(otherTransport.appProtocol == nil, "a TCP rule does not apply to UDP")
    }

    @Test
    func invalidRulesAreNotApplied() {
        #expect(!DecodeAsRule(transport: .udp, port: 0, decode: .dns).isValid)
        #expect(!DecodeAsRule(transport: .tcp, port: 8_080, decode: .quic).isValid, "QUIC rides on UDP only")
        #expect(DecodeAsRule(transport: .tcp, port: 8_080, decode: .http).isValid)
    }

    @Test
    func packetDetailsDecodeAsTargetsUseTCPAndUDPPortsEvenAfterFieldProjection() throws {
        let tcp = DecodedLayer(
            proto: .tcp, title: "Transmission Control Protocol", fields: [
                DecodedField(name: "Source Port", value: "51234"),
                DecodedField(name: "Destination Port", value: "443"),
                DecodedField(name: "Window Size", value: "4096"),
            ]
        )
        let udp = DecodedLayer(
            proto: .udp, title: "User Datagram Protocol", fields: [
                DecodedField(name: "Source Port", value: "5353"),
                DecodedField(name: "Destination Port", value: "not a port"),
            ]
        )
        let sctp = DecodedLayer(
            proto: .sctp, title: "Stream Control Transmission Protocol", fields: [
                DecodedField(name: "Source Port", value: "2905"),
            ]
        )

        #expect(DecodeAsPacketTargets.from(tcp) == [
            DecodeAsPacketTarget(transport: .tcp, endpoint: .source, port: 51_234),
            DecodeAsPacketTarget(transport: .tcp, endpoint: .destination, port: 443),
        ])
        #expect(DecodeAsPacketTargets.from(udp) == [
            DecodeAsPacketTarget(transport: .udp, endpoint: .source, port: 5_353),
        ])
        #expect(DecodeAsPacketTargets.from(sctp).isEmpty)

        let filteredTCP = try #require(DecodedLayerSearchProjection.filter([tcp], query: "window").first)
        #expect(filteredTCP.fields.map(\.name) == ["Window Size"])
        #expect(DecodeAsPacketTargets.from(filteredTCP) == DecodeAsPacketTargets.from(tcp))
    }

    @MainActor
    @Test
    func settingsPersistPerProject() throws {
        let suite = "decode-as-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        let settings = DecodeAsSettings()
        settings.publishesToDecoder = false
        settings.bind(to: defaults)
        #expect(settings.rules.isEmpty)
        settings.setRules([DecodeAsRule(transport: .udp, port: 5_300, decode: .dns)])
        #expect(settings.needsRedecode)
        let reopened = DecodeAsSettings()
        reopened.publishesToDecoder = false
        reopened.bind(to: defaults)
        #expect(reopened.rules.map(\.port) == [5_300])
        #expect(!reopened.needsRedecode)
    }

    @MainActor
    @Test
    func packetDerivedRuleStaysADraftUntilApplied() throws {
        let suite = "decode-as-draft-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        let settings = DecodeAsSettings()
        settings.publishesToDecoder = false
        settings.bind(to: defaults)

        settings.prepareRuleDraft(transport: .udp, port: 5_300)
        #expect(settings.rules.isEmpty)
        #expect(settings.ruleDraft?.transport == .udp)
        #expect(settings.ruleDraft?.port == 5_300)
        #expect(settings.ruleDraft?.decode.transports.contains(.udp) == true)
        #expect(defaults.data(forKey: ProjectScopedSettingsKeys.decodeAsRules) == nil)
        #expect(settings.canApplyRuleDraft)

        var draft = try #require(settings.ruleDraft)
        settings.updateRuleDraft(.dns, at: \.decode, draftID: draft.id)
        draft.decode = .dns
        settings.applyRuleDraft()

        #expect(settings.rules == [draft])
        #expect(settings.ruleDraft == nil)
        #expect(settings.needsRedecode)
        #expect(defaults.data(forKey: ProjectScopedSettingsKeys.decodeAsRules) != nil)
    }

    @MainActor
    @Test
    func switchingProjectDiscardsAnUnappliedRuleDraft() throws {
        let firstSuite = "decode-as-first-\(UUID().uuidString)"
        let secondSuite = "decode-as-second-\(UUID().uuidString)"
        let firstDefaults = try #require(UserDefaults(suiteName: firstSuite))
        let secondDefaults = try #require(UserDefaults(suiteName: secondSuite))
        defer {
            TestPreferences.remove(firstSuite)
            TestPreferences.remove(secondSuite)
        }
        let settings = DecodeAsSettings()
        settings.publishesToDecoder = false
        settings.bind(to: firstDefaults)
        settings.prepareRuleDraft(transport: .tcp, port: 8_080)

        settings.bind(to: secondDefaults)

        #expect(settings.ruleDraft == nil)
        #expect(settings.rules.isEmpty)
        #expect(firstDefaults.data(forKey: ProjectScopedSettingsKeys.decodeAsRules) == nil)
        #expect(secondDefaults.data(forKey: ProjectScopedSettingsKeys.decodeAsRules) == nil)
    }

    @MainActor
    @Test
    func packetDerivedDraftReplacesAnExistingPortRuleWithoutDuplicatingIt() throws {
        let settings = DecodeAsSettings()
        settings.publishesToDecoder = false
        let original = DecodeAsRule(transport: .tcp, port: 8_080, decode: .http)
        settings.setRules([original])

        settings.prepareRuleDraft(transport: .tcp, port: 8_080)
        #expect(settings.ruleDraftReplacesExisting)
        var draft = try #require(settings.ruleDraft)
        settings.updateRuleDraft(.tls, at: \.decode, draftID: draft.id)
        draft.decode = .tls
        settings.applyRuleDraft()

        #expect(settings.rules.count == 1)
        #expect(settings.rules[0] == draft)
    }

    @MainActor
    @Test
    func staleDraftEditorCannotChangeANewerProposal() throws {
        let settings = DecodeAsSettings()
        settings.publishesToDecoder = false
        settings.prepareRuleDraft(transport: .tcp, port: 8_080)
        let oldDraftID = try #require(settings.ruleDraft).id

        settings.prepareRuleDraft(transport: .udp, port: 5_353)
        settings.updateRuleDraft(9_999, at: \.port, draftID: oldDraftID)

        #expect(settings.ruleDraft?.transport == .udp)
        #expect(settings.ruleDraft?.port == 5_353)
    }

    @MainActor
    @Test
    func ruleLimitRejectsNewProposalButAllowsReplacement() throws {
        let settings = DecodeAsSettings()
        settings.publishesToDecoder = false
        let rules = (0 ..< DecodeAsSettings.maximumRules).map { index in
            DecodeAsRule(transport: .tcp, port: UInt16(1_000 + index), decode: .http)
        }
        settings.setRules(rules)

        settings.prepareRuleDraft(transport: .udp, port: 9_999)
        #expect(settings.ruleDraftCapacityReached)
        #expect(!settings.canApplyRuleDraft)
        settings.applyRuleDraft()
        #expect(settings.rules.count == DecodeAsSettings.maximumRules)
        #expect(settings.ruleDraft?.port == 9_999)

        settings.prepareRuleDraft(transport: .tcp, port: 1_000)
        #expect(settings.ruleDraftReplacesExisting)
        #expect(!settings.ruleDraftCapacityReached)
        #expect(settings.canApplyRuleDraft)
        let draft = try #require(settings.ruleDraft)
        settings.updateRuleDraft(.tls, at: \.decode, draftID: draft.id)
        settings.applyRuleDraft()
        #expect(settings.rules.count == DecodeAsSettings.maximumRules)
        #expect(settings.rules[0].decode == .tls)
    }

    // MARK: Private

    private func decode(_ frame: [UInt8], rules: [DecodeAsRule]) -> DecodedPacket {
        DecodeAs.$scopedRules.withValue(rules) {
            SessionBuilder.decodePacket(
                CapturedFrame(bytes: frame, timestamp: Date(), originalLength: frame.count),
                linkType: LinkType.ethernet
            )
        }
    }
}
