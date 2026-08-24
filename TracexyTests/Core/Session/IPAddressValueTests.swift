import Foundation
import Testing
@testable import Tracexy

// MARK: - IPAddressValueTests

/// Exact-parse, boundary, normalization and containment coverage for the validated
/// binary IP/CIDR values. Everything is pure: no network IO, no DNS, no regex.
struct IPAddressValueTests {
    // MARK: IPv4/IPv6 exact parsing

    @Test
    func parsesIPv4IntoFourNetworkOrderBytes() throws {
        let value = try #require(IPAddressValue(parsing: "192.0.2.5"))
        #expect(value.family == .v4)
        #expect(value.bytes == [192, 0, 2, 5])
    }

    @Test
    func parsesIPv6IntoSixteenNetworkOrderBytes() throws {
        let value = try #require(IPAddressValue(parsing: "2001:db8::1"))
        #expect(value.family == .v6)
        #expect(value.bytes == [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    }

    @Test
    func compressedAndExpandedIPv6CompareEqual() throws {
        let compressed = try #require(IPAddressValue(parsing: "2001:db8::1"))
        let expanded = try #require(IPAddressValue(parsing: "2001:0db8:0000:0000:0000:0000:0000:0001"))
        #expect(compressed == expanded)
        #expect(compressed.hashValue == expanded.hashValue)
    }

    // MARK: Address boundaries

    @Test
    func parsesIPv4Boundaries() {
        #expect(IPAddressValue(parsing: "0.0.0.0")?.bytes == [0, 0, 0, 0])
        #expect(IPAddressValue(parsing: "255.255.255.255")?.bytes == [255, 255, 255, 255])
    }

    @Test
    func parsesIPv6Boundaries() throws {
        #expect(IPAddressValue(parsing: "::")?.bytes == [UInt8](repeating: 0, count: 16))
        let allOnes = try #require(IPAddressValue(parsing: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
        #expect(allOnes.bytes == [UInt8](repeating: 0xFF, count: 16))
    }

    // MARK: Determinism

    @Test
    func repeatedParsingIsDeterministic() throws {
        let first = try #require(IPAddressValue(parsing: "198.51.100.7"))
        let second = try #require(IPAddressValue(parsing: "198.51.100.7"))
        #expect(first == second)
        #expect(first.hashValue == second.hashValue)
        #expect(Set([first, second]).count == 1)
    }

    // MARK: Malformed addresses fail closed

    @Test
    func rejectsMalformedAddresses() {
        let bad = [
            "", " ", "   ",
            " 192.0.2.5", "192.0.2.5 ", "192.0. 2.5",
            "fe80::1%en0", "fe80::1%25en0",
            "192.0.2.256", "192.0.2", "192.0.2.5.6", "1.2.3.4/24",
            "2001:db8:::1", "2001:db8::g",
            "[::1]", "::1]", "[2001:db8::1",
            "example.com", "0x7f.0.0.1", "192.0.2.5:80",
            "192.0.2.5\0suffix", "2001:db8::1\0suffix",
        ]
        for text in bad {
            #expect(IPAddressValue(parsing: text) == nil, "should reject \(text)")
        }
    }

    // MARK: CIDR boundaries, /0, /32, /128, host prefixes

    @Test
    func parsesIPv4CIDRRange() {
        #expect(CIDRValue(parsing: "10.0.0.0/0")?.prefixLength == 0)
        #expect(CIDRValue(parsing: "10.0.0.0/8")?.prefixLength == 8)
        #expect(CIDRValue(parsing: "192.0.2.5/32")?.prefixLength == 32)
        #expect(CIDRValue(parsing: "192.0.2.5/33") == nil)
    }

    @Test
    func parsesIPv6CIDRRange() {
        #expect(CIDRValue(parsing: "::/0")?.prefixLength == 0)
        #expect(CIDRValue(parsing: "2001:db8::/32")?.prefixLength == 32)
        #expect(CIDRValue(parsing: "2001:db8::1/128")?.prefixLength == 128)
        #expect(CIDRValue(parsing: "2001:db8::1/129") == nil)
    }

    // MARK: Host-bit normalization

    @Test
    func normalizesIPv4HostBits() throws {
        // 192.0.2.130/24 → network 192.0.2.0, and two host addresses collapse equal.
        let block = try #require(CIDRValue(parsing: "192.0.2.130/24"))
        #expect(block.network.bytes == [192, 0, 2, 0])
        #expect(block == CIDRValue(parsing: "192.0.2.5/24"))
    }

    @Test
    func normalizesPartialByteBoundary() throws {
        // /28 keeps the high nibble of the last byte, clears the low nibble.
        let block = try #require(CIDRValue(parsing: "192.0.2.201/28"))
        #expect(block.network.bytes == [192, 0, 2, 0xC0])
    }

    @Test
    func normalizesIPv6HostBits() throws {
        let block = try #require(CIDRValue(parsing: "2001:db8:abcd:ef01::1234/32"))
        #expect(block.network.bytes == [0x20, 0x01, 0x0D, 0xB8] + [UInt8](repeating: 0, count: 12))
    }

    @Test
    func slashZeroNormalizesToAllZeroNetwork() {
        #expect(CIDRValue(parsing: "203.0.113.9/0")?.network.bytes == [0, 0, 0, 0])
        #expect(CIDRValue(parsing: "2001:db8::1/0")?.network.bytes == [UInt8](repeating: 0, count: 16))
    }

    // MARK: Containment hit/miss

    @Test
    func containmentHitAndMiss() throws {
        let block = try #require(CIDRValue(parsing: "192.0.2.0/24"))
        #expect(try block.contains(#require(IPAddressValue(parsing: "192.0.2.0"))))
        #expect(try block.contains(#require(IPAddressValue(parsing: "192.0.2.255"))))
        #expect(try !block.contains(#require(IPAddressValue(parsing: "192.0.3.0"))))
        #expect(try !block.contains(#require(IPAddressValue(parsing: "198.51.100.1"))))
    }

    @Test
    func slashThirtyTwoContainsOnlyItself() throws {
        let block = try #require(CIDRValue(parsing: "192.0.2.5/32"))
        #expect(try block.contains(#require(IPAddressValue(parsing: "192.0.2.5"))))
        #expect(try !block.contains(#require(IPAddressValue(parsing: "192.0.2.6"))))
    }

    @Test
    func slashOneTwentyEightContainsOnlyItself() throws {
        let block = try #require(CIDRValue(parsing: "2001:db8::5/128"))
        #expect(try block.contains(#require(IPAddressValue(parsing: "2001:db8::5"))))
        #expect(try !block.contains(#require(IPAddressValue(parsing: "2001:db8::6"))))
    }

    @Test
    func slashZeroContainsEverySameFamilyAddress() throws {
        let v4 = try #require(CIDRValue(parsing: "0.0.0.0/0"))
        #expect(try v4.contains(#require(IPAddressValue(parsing: "8.8.8.8"))))
        let v6 = try #require(CIDRValue(parsing: "::/0"))
        #expect(try v6.contains(#require(IPAddressValue(parsing: "2001:db8::1"))))
    }

    @Test
    func ipv6ContainmentHitAndMiss() throws {
        let block = try #require(CIDRValue(parsing: "2001:db8::/32"))
        #expect(try block.contains(#require(IPAddressValue(parsing: "2001:db8:ffff::1"))))
        #expect(try !block.contains(#require(IPAddressValue(parsing: "2001:db9::1"))))
    }

    // MARK: Mixed family never matches

    @Test
    func mixedFamilyContainmentAlwaysFails() throws {
        let v4Block = try #require(CIDRValue(parsing: "0.0.0.0/0"))
        #expect(try !v4Block.contains(#require(IPAddressValue(parsing: "2001:db8::1"))))
        let v6Block = try #require(CIDRValue(parsing: "::/0"))
        #expect(try !v6Block.contains(#require(IPAddressValue(parsing: "192.0.2.1"))))
    }

    // MARK: Malformed CIDR fails closed

    @Test
    func rejectsMalformedCIDR() {
        let bad = [
            "", "192.0.2.0", // missing slash
            "192.0.2.0/", "/24", // empty side
            "192.0.2.0/24/8", "192.0.2.0//24", // duplicate slash
            "192.0.2.0/+24", "192.0.2.0/-1", // signed prefix
            "192.0.2.0/0x8", "192.0.2.0/ 8", "192.0.2.0/8 ", // non-decimal / whitespace prefix
            "192.0.2.0/33", "2001:db8::/129", // overflowed range
            "192.0.2.0/64", // mixed-family: v4 with a v6-range prefix
            "192.0.2.0/999999999999999999999999", // overflows Int
            "192.0.2.256/24", "fe80::1%en0/64", // malformed address side
            "192.0.2.5\0suffix/24", // embedded C-string terminator
        ]
        for text in bad {
            #expect(CIDRValue(parsing: text) == nil, "should reject \(text)")
        }
    }

    @Test
    func repeatedCIDRParsingIsDeterministic() throws {
        let first = try #require(CIDRValue(parsing: "10.10.0.0/16"))
        let second = try #require(CIDRValue(parsing: "10.10.5.5/16"))
        #expect(first == second)
        #expect(first.hashValue == second.hashValue)
        #expect(Set([first, second]).count == 1)
    }
}
