import Foundation
import Testing
@testable import Tracexy

// MARK: - AssistantLocalEndpointTests

@Suite("Assistant endpoint: only this Mac, no credentials, no arbitrary schemes")
struct AssistantLocalEndpointTests {
    @Test("The loopback literals are accepted", arguments: [
        "http://127.0.0.1:11434",
        "http://[::1]:11434",
        "https://127.0.0.1:8443",
        "http://127.0.0.1:1234/v1",
        "http://127.0.0.1:1234/v1/",
    ])
    func loopbackIsAccepted(_ text: String) throws {
        let endpoint = try AssistantLocalEndpoint.validate(text)
        let expected = text.hasSuffix("/") ? String(text.dropLast()) : text
        #expect(endpoint.displayText == expected)
        // A trailing slash is normalized away so path joining stays predictable.
        #expect(!endpoint.baseURL.path.hasSuffix("/"))
    }

    @Test("localhost is rewritten to the numeric loopback literal, keeping scheme, port and path", arguments: [
        ("http://localhost:11434", "http://127.0.0.1:11434"),
        ("http://LOCALHOST:11434/", "http://127.0.0.1:11434"),
        ("https://localhost:8443/v1/", "https://127.0.0.1:8443/v1"),
        ("http://localhost", "http://127.0.0.1"),
    ])
    func localhostIsCanonicalized(_ text: String, _ expected: String) throws {
        let endpoint = try AssistantLocalEndpoint.validate(text)
        #expect(endpoint.displayText == expected)
        #expect(endpoint.baseURL.host() == AssistantLocalEndpoint.mappedHostLiteral)
        // The name never survives into a request URL.
        #expect(!endpoint.url(path: "api/chat").absoluteString.contains("localhost"))
    }

    @Test("A localhost redirect target is followed only through the numeric literal")
    func redirectTargetIsCanonicalized() throws {
        let named = try #require(URL(string: "http://localhost:11434/api/chat"))
        let canonical = try #require(AssistantLocalEndpoint.canonicalLoopbackURL(named))
        #expect(canonical.absoluteString == "http://127.0.0.1:11434/api/chat")

        let literal = try #require(URL(string: "http://[::1]:11434/api/chat"))
        #expect(AssistantLocalEndpoint.canonicalLoopbackURL(literal)?.absoluteString == literal.absoluteString)

        let remote = try #require(URL(string: "http://localhost.example.com/api/chat"))
        #expect(AssistantLocalEndpoint.canonicalLoopbackURL(remote) == nil)
    }

    @Test("Anything not on this Mac is refused", arguments: [
        "http://192.168.1.10:11434",
        "http://10.0.0.5:11434",
        "https://api.example.com/v1",
        "http://127.0.0.2:11434",
        "http://[::1%lo0]:11434",
        "http://0.0.0.0:11434",
    ])
    func nonLoopbackIsRefused(_ text: String) {
        #expect(throws: (any Error).self) {
            try AssistantLocalEndpoint.validate(text)
        }
    }

    @Test("HTTPS to a remote host is refused as not-loopback, not accepted as secure")
    func httpsToRemoteIsRefused() {
        #expect(throws: AssistantEndpointError.notLoopback("model.example.com")) {
            try AssistantLocalEndpoint.validate("https://model.example.com/v1")
        }
    }

    @Test("Arbitrary schemes are refused")
    func schemesAreClosed() {
        #expect(throws: AssistantEndpointError.unsupportedScheme("file")) {
            try AssistantLocalEndpoint.validate("file:///etc/passwd")
        }
        #expect(throws: AssistantEndpointError.unsupportedScheme("ws")) {
            try AssistantLocalEndpoint.validate("ws://127.0.0.1:11434")
        }
    }

    @Test("A URL carrying credentials is refused before anything is sent")
    func credentialsAreRefused() {
        #expect(throws: AssistantEndpointError.embeddedCredentials) {
            try AssistantLocalEndpoint.validate("http://user:secret@127.0.0.1:11434")
        }
    }

    @Test("A query, a fragment or an absurd path is refused")
    func componentsAreBounded() {
        #expect(throws: AssistantEndpointError.unsupportedComponents) {
            try AssistantLocalEndpoint.validate("http://127.0.0.1:11434/v1?key=abc")
        }
        #expect(throws: AssistantEndpointError.unsupportedComponents) {
            try AssistantLocalEndpoint.validate("http://127.0.0.1:11434/v1#frag")
        }
        let longPath = "/" + String(repeating: "a", count: AssistantLocalEndpoint.maxPathLength + 1)
        #expect(throws: AssistantEndpointError.pathTooLong) {
            try AssistantLocalEndpoint.validate("http://127.0.0.1:11434\(longPath)")
        }
    }

    @Test("Empty and malformed input are typed refusals with actionable copy")
    func emptyAndMalformed() {
        #expect(throws: AssistantEndpointError.empty) {
            try AssistantLocalEndpoint.validate("   ")
        }
        #expect(!AssistantEndpointError.notLoopback("example.com").message.isEmpty)
    }

    @Test("The redirect guard's loopback check matches the entry rules")
    func redirectGuardCheck() {
        #expect(AssistantLocalEndpoint.isLoopback(URL(fileURLWithPath: "/tmp")) == false)
        #expect(AssistantLocalEndpoint
            .isLoopback(URL(string: "http://127.0.0.1:11434/api/chat") ?? URL(fileURLWithPath: "/")))
        #expect(AssistantLocalEndpoint.isLoopback(URL(string: "http://localhost/api") ?? URL(fileURLWithPath: "/")))
        #expect(!AssistantLocalEndpoint
            .isLoopback(URL(string: "http://evil.example.com/api") ?? URL(fileURLWithPath: "/")))
        #expect(!AssistantLocalEndpoint
            .isLoopback(URL(string: "http://u:p@127.0.0.1/api") ?? URL(fileURLWithPath: "/")))
    }

    @Test("The default endpoint is the local Ollama daemon")
    func defaultEndpoint() throws {
        let endpoint = try AssistantLocalEndpoint.standard()
        #expect(endpoint.displayText == "http://127.0.0.1:11434")
        #expect(endpoint.url(path: "api/chat").absoluteString == "http://127.0.0.1:11434/api/chat")
    }
}
