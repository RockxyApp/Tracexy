import Foundation
import Testing
@testable import Tracexy

@Suite("Wireshark hosts import")
@MainActor
struct WiresharkHostsImporterTests {
    @Test
    func parsesIPv4IPv6CommentsAliasesAndLastDuplicate() throws {
        let source = """
        # Project router
        192.0.2.1 gateway router # comment
        2001:DB8::1 files.example
        192.0.2.1 edge
        not-an-ip ignored
        192.0.2.2
        192.0.2.3 bad\u{0000}name
        """
        let input = source + "\n192.0.2.4 " + String(repeating: "x", count: 65)
        let result = try WiresharkHostsImporter.parse(Data(("\u{FEFF}" + input).utf8))
        #expect(result.names == [
            "192.0.2.1": "edge",
            "192.0.2.4": String(repeating: "x", count: AddressNameBook.maximumNameCharacters),
            "2001:db8::1": "files.example",
        ])
        #expect(result.malformedLines == 3)
        #expect(result.ignoredAliases == 1)
        #expect(result.truncatedNames == 1)
        #expect(result.repeatedAddresses == 1)
        #expect(result.conflictingAddresses == 1)
    }

    @Test
    func boundsInputAndRequiresUsableEntries() throws {
        #expect(throws: WiresharkHostsImporter.ImportError.fileTooLarge) {
            try WiresharkHostsImporter.parse(Data(repeating: 0x20, count: WiresharkHostsImporter.maximumFileBytes + 1))
        }
        let tooManyLines = String(repeating: "\n", count: WiresharkHostsImporter.maximumLines + 1)
        #expect(throws: WiresharkHostsImporter.ImportError.tooManyLines) {
            try WiresharkHostsImporter.parse(Data(tooManyLines.utf8))
        }
        #expect(throws: WiresharkHostsImporter.ImportError.noUsableEntries) {
            try WiresharkHostsImporter.parse(Data("# comments only\ninvalid text\n".utf8))
        }
        let tooManyAddresses = (1 ... WiresharkHostsImporter.maximumAddresses + 1).map { index in
            "10.\(index / 65_536).\((index / 256) % 256).\(index % 256) host\(index)"
        }.joined(separator: "\n")
        #expect(throws: WiresharkHostsImporter.ImportError.tooManyAddresses) {
            try WiresharkHostsImporter.parse(Data(tooManyAddresses.utf8))
        }
    }

    @Test
    func addsOnlyPreviouslyUnnamedAddressesAndPreservesExistingLabels() throws {
        let suite = "com.amunx.tracexy.tests.host-import.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        let book = AddressNameBook()
        book.bind(to: defaults)
        #expect(book.setName("Existing", for: "192.0.2.1"))

        let result = book.importNames([
            "192.0.2.1": "Imported replacement",
            "192.0.2.2": " New host ",
            "not-an-ip": "Invalid",
        ])
        #expect(result == AddressNameImportResult(added: 1, alreadyNamed: 1, invalid: 1, full: false))
        #expect(book.name(for: "192.0.2.1") == "Existing")
        #expect(book.name(for: "192.0.2.2") == "New host")

        let reopenedBook = AddressNameBook()
        reopenedBook.bind(to: defaults)
        #expect(reopenedBook.names == book.names)
    }

    @Test
    func fillsAnEmptyAddressBookToItsLimit() throws {
        let suite = "com.amunx.tracexy.tests.host-import-capacity.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { TestPreferences.remove(suite) }
        let fullBook = AddressNameBook()
        fullBook.bind(to: defaults)
        #expect(fullBook.names.isEmpty)
        let fullMap = Dictionary(uniqueKeysWithValues: (1 ... AddressNameBook.maximumEntries).map { index in
            ("198.18.\((index / 256) % 256).\(index % 256)", "host\(index)")
        })
        #expect(fullBook.importNames(fullMap).added == AddressNameBook.maximumEntries)
        #expect(fullBook.names.count == AddressNameBook.maximumEntries)
        let overflow = fullBook.importNames(["203.0.113.1": "extra"])
        #expect(overflow.full)
        #expect(fullBook.name(for: "203.0.113.1") == nil)
    }
}
