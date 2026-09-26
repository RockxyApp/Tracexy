import Observation
import SwiftUI

// MARK: - AddressLocationColumn

/// The location columns an address table can add when a locator is installed.
enum AddressLocationColumn: CaseIterable, Hashable {
    case country
    case city
    case asNumber
    case asOrganization
}

// MARK: - AddressLocationMenuItem

/// A Session Expression offered from an address's context menu, such as the
/// sessions with the same country.
struct AddressLocationMenuItem: Hashable, Identifiable {
    let title: String
    let expression: String

    var id: String {
        expression
    }
}

// MARK: - AddressLocating

/// Where addresses are, as databases the user chose place them, which the
/// composition root may supply.
///
/// Address tables ask it for extra columns, the Session Inspector for extra decode
/// layers. Without one, nothing is added and every surface looks as it does
/// without location data. A locator only adds to what is drawn: it never changes
/// sessions, frames or what is exported.
@MainActor
protocol AddressLocating: AnyObject {
    /// Whether answers are available now. Address tables add their location
    /// columns only then.
    var isLocating: Bool { get }

    func columnTitle(_ column: AddressLocationColumn) -> String

    /// The cell for `address` (canonical IP text) in `column`.
    func cell(_ column: AddressLocationColumn, for address: String) -> AnyView

    /// Whether the location of `address` matches a table's search text.
    func matches(_ address: String, filter: String) -> Bool

    /// Session Expressions offered from `address`'s context menu.
    func menuItems(for address: String) -> [AddressLocationMenuItem]

    /// Controls for the Endpoints window's footer, or `nil`.
    func endpointsAccessory() -> AnyView?

    /// Decode layers the Session Inspector adds after `session`'s own.
    func inspectorLayers(for session: SessionSummary) -> [DecodedLayer]
}

// MARK: - AddressLocators

/// Where the composition root installs its locator, once, at launch. Held weakly:
/// the composition root owns it. `nil` adds nothing anywhere.
///
/// Reading ``installed`` is observed, so a window drawn before the locator is
/// installed (Endpoints or an inspector restored ahead of the main window) redraws
/// when it arrives.
@MainActor
enum AddressLocators {
    // MARK: Internal

    static var installed: (any AddressLocating)? {
        get {
            _ = slot.installations
            return slot.locator
        }
        set {
            guard slot.locator !== newValue else {
                return
            }
            slot.locator = newValue
            slot.installations &+= 1
        }
    }

    // MARK: Private

    private static let slot = AddressLocatorSlot()
}

// MARK: - AddressLocatorSlot

/// Holds the installed instance; its counter makes reading it observable.
@MainActor
@Observable
private final class AddressLocatorSlot {
    @ObservationIgnored weak var locator: (any AddressLocating)?
    var installations = 0
}
