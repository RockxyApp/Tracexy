import AppKit
import SwiftUI

// MARK: - GeoIPController + AddressLocating

extension GeoIPController: AddressLocating {
    var isLocating: Bool {
        hasReadyDatabase
    }

    func columnTitle(_ column: AddressLocationColumn) -> String {
        switch column {
        case .country: String(localized: "Country")
        case .city: String(localized: "City")
        case .asNumber: String(localized: "AS Number")
        case .asOrganization: String(localized: "AS Organization")
        }
    }

    func cell(_ column: AddressLocationColumn, for address: String) -> AnyView {
        AnyView(GeoIPLocationCell(answer: answer(for: address), column: column))
    }

    func matches(_ address: String, filter: String) -> Bool {
        guard case let .located(location) = answer(for: address) else {
            return false
        }
        return [location.country, location.countryCode, location.city, location.asNumberText, location.asOrganization]
            .contains { $0?.localizedCaseInsensitiveContains(filter) ?? false }
    }

    func menuItems(for address: String) -> [AddressLocationMenuItem] {
        guard case let .located(location) = answer(for: address) else {
            return []
        }
        var items: [AddressLocationMenuItem] = []
        if let code = location.countryCode, let name = location.countryText {
            items.append(AddressLocationMenuItem(
                title: String(localized: "Show Sessions in \(name)"),
                expression: GeoIPExpressionBuiltIns.use(.country, value: code)
            ))
        }
        if let number = location.asNumber, let text = location.asNumberText {
            items.append(AddressLocationMenuItem(
                title: String(localized: "Show Sessions in \(text)"),
                expression: GeoIPExpressionBuiltIns.use(.asn, value: String(number))
            ))
        }
        return items
    }

    func endpointsAccessory() -> AnyView? {
        AnyView(GeoIPEndpointsAccessory(controller: self))
    }

    func inspectorLayers(for session: SessionSummary) -> [DecodedLayer] {
        guard hasReadyDatabase else {
            return []
        }
        if let cached = inspectorLayerCache[session.id] {
            return cached
        }
        var children: [DecodedLayer] = []
        if let source = session.sourceEndpointValue?.ip {
            children.append(Self.layer(
                title: String(localized: "Source GeoIP"),
                address: source,
                answer: answer(for: source)
            ))
        }
        if let destination = session.destinationEndpointValue?.ip {
            children.append(Self.layer(
                title: String(localized: "Destination GeoIP"),
                address: destination,
                answer: answer(for: destination)
            ))
        }
        let layers = children.isEmpty ? [] : [DecodedLayer(
            proto: .other,
            title: String(localized: "GeoIP"),
            children: children
        )]
        if inspectorLayerCache.count >= 256 {
            inspectorLayerCache.removeAll()
        }
        inspectorLayerCache[session.id] = layers
        return layers
    }

    private static func layer(title: String, address: String, answer: GeoIPAnswer) -> DecodedLayer {
        var fields: [DecodedField] = []
        switch answer {
        case let .located(location):
            if let country = location.country, let code = location.countryCode {
                fields.append(DecodedField(
                    name: String(localized: "Country"),
                    value: "\(country) (\(code))"
                ))
            } else if let country = location.countryText {
                fields.append(DecodedField(name: String(localized: "Country"), value: country))
            }
            if let city = location.city {
                fields.append(DecodedField(name: String(localized: "City"), value: city))
            }
            if let number = location.asNumberText {
                fields.append(DecodedField(name: String(localized: "AS Number"), value: number))
            }
            if let organization = location.asOrganization {
                fields.append(DecodedField(
                    name: String(localized: "AS Organization"),
                    value: organization
                ))
            }
            if let network = location.network {
                fields.append(DecodedField(name: String(localized: "Network"), value: network))
            }
        case let .notLookedUp(scope):
            fields.append(DecodedField(name: scope.label, value: scope.explanation))
        case .notFound,
             .notAnAddress:
            fields.append(DecodedField(
                name: String(localized: "Location"),
                value: String(localized: "Not in the chosen databases.")
            ))
        case .unreadable:
            fields.append(DecodedField(
                name: String(localized: "Location"),
                value: String(localized: "The database entry for this address couldn’t be read.")
            ))
        }
        return DecodedLayer(proto: .other, title: title, summary: address, fields: fields)
    }
}

// MARK: - GeoIPLocationCell

/// One location cell of an address table.
struct GeoIPLocationCell: View {
    // MARK: Internal

    let answer: GeoIPAnswer
    let column: AddressLocationColumn

    var body: some View {
        switch answer {
        case let .located(location):
            if let text = value(location) {
                Text(text)
                    .font(column == .asNumber ? Theme.Typography.mono : Theme.Typography.body)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .help(help(location) ?? text)
            } else {
                dash(String(localized: "The chosen databases don’t say"))
            }
        case let .notLookedUp(scope):
            if column == .country {
                Text(scope.label)
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
                    .help(scope.explanation)
            } else {
                dash(scope.explanation)
            }
        case .notFound:
            dash(String(localized: "Not in the chosen databases"))
        case .unreadable:
            dash(String(localized: "The database entry for this address couldn’t be read"))
        case .notAnAddress:
            Text(verbatim: "")
        }
    }

    // MARK: Private

    private func dash(_ help: String) -> some View {
        Text(verbatim: "—")
            .foregroundStyle(.tertiary)
            .help(help)
    }

    private func value(_ location: GeoIPLocation) -> String? {
        switch column {
        case .country: location.countryText
        case .city: location.city
        case .asNumber: location.asNumberText
        case .asOrganization: location.asOrganization
        }
    }

    private func help(_ location: GeoIPLocation) -> String? {
        switch column {
        case .country: location.countryCode
        case .asNumber,
             .asOrganization: location.network
        case .city: nil
        }
    }
}

// MARK: - GeoIPEndpointsAccessory

/// GeoIP Databases… in the Endpoints window's footer. Opens the sheet on the
/// Endpoints window itself.
struct GeoIPEndpointsAccessory: View {
    // MARK: Internal

    let controller: GeoIPController

    var body: some View {
        Button {
            isPresented = true
        } label: {
            Text("GeoIP Databases…")
        }
        .help(Text("Choose MaxMind databases to show where each public address is"))
        .accessibilityIdentifier("geoip.endpointsButton")
        .sheet(isPresented: $isPresented) {
            GeoIPDatabasesSheet(controller: controller) {
                isPresented = false
            }
        }
    }

    // MARK: Private

    @State private var isPresented = false
}

// MARK: - GeoIPDatabasesSheet

/// Statistics ▸ GeoIP Databases…: the active Project's database files.
struct GeoIPDatabasesSheet: View {
    // MARK: Internal

    let controller: GeoIPController
    let onDone: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingL) {
            VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
                Text(
                    "Tracexy shows where public addresses are from MaxMind databases you choose, such as GeoLite2 City, Country and ASN, or DB-IP files in the same format."
                )
                .fixedSize(horizontal: false, vertical: true)
                Text(
                    "Lookups happen on this Mac. Tracexy never downloads databases or sends addresses anywhere."
                )
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                Text(
                    "Private, link-local and loopback addresses are never looked up. This Project remembers where the files are."
                )
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                Text(
                    "In a Session Expression, $geoip_country(DE), $geoip_city(Berlin), $geoip_asn(3320) and $geoip_org(Telekom) find sessions by location."
                )
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
            }

            table
                .frame(height: 170)
                .overlay {
                    if controller.entries.isEmpty {
                        Text("No databases are chosen for this Project.")
                            .foregroundStyle(.secondary)
                            .accessibilityIdentifier("geoip.empty")
                    }
                }

            if let notice = controller.addNotice {
                Label(notice, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("geoip.addNotice")
            }

            HStack(spacing: Theme.Metrics.spacingM) {
                Button(role: .destructive) {
                    if let selection {
                        controller.removeDatabase(selection)
                        self.selection = nil
                    }
                } label: {
                    Text("Remove")
                }
                .disabled(selection == nil)
                .help(Text("Forget the selected database for this Project"))
                .accessibilityIdentifier("geoip.remove")
                Spacer()
                Button {
                    controller.reloadAll()
                } label: {
                    Text("Reload")
                }
                .disabled(controller.entries.isEmpty)
                .help(Text("Read every file again, after a database update"))
                .accessibilityIdentifier("geoip.reload")
                Button {
                    controller.addDatabases()
                } label: {
                    Text("Add…")
                }
                .disabled(!controller.canAddDatabases)
                .help(controller.canAddDatabases
                    ? Text("Choose database files for this Project")
                    : Text("Databases can be added up to \(controller.databaseLimit) per Project"))
                .accessibilityIdentifier("geoip.add")
                Button(action: onDone) {
                    Text("Done")
                }
                .keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("geoip.done")
            }
        }
        .padding(20)
        .frame(width: 620)
        .accessibilityIdentifier("geoip.sheet")
    }

    // MARK: Private

    @State private var selection: GeoIPDatabaseEntry.ID?

    private var table: some View {
        Table(controller.entries, selection: $selection) {
            TableColumn(Text("File")) { entry in
                Text(entry.fileName)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help(entry.url?.path ?? entry.fileName)
            }
            .width(min: 110, ideal: 160)
            TableColumn(Text("Type")) { entry in
                switch entry.status {
                case .reading:
                    HStack(spacing: Theme.Metrics.spacingS) {
                        ProgressView().controlSize(.small)
                        Text("Reading…").foregroundStyle(.secondary)
                    }
                case let .ready(info):
                    Text(info.databaseType).lineLimit(1)
                case let .unavailable(reason):
                    Label(reason, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .help(reason)
                }
            }
            .width(min: 120, ideal: 170)
            TableColumn(Text("Built")) { entry in
                if case let .ready(info) = entry.status, let date = info.buildDate {
                    Text(date.formatted(date: .abbreviated, time: .omitted)).monospacedDigit()
                } else {
                    Text(verbatim: "—").foregroundStyle(.tertiary)
                }
            }
            .width(min: 80, ideal: 90)
            TableColumn(Text("Networks")) { entry in
                if case let .ready(info) = entry.status {
                    Text(info.networkCount.formatted()).monospacedDigit()
                } else {
                    Text(verbatim: "—").foregroundStyle(.tertiary)
                }
            }
            .width(min: 70, ideal: 80)
        }
        .accessibilityIdentifier("geoip.table")
    }
}

// MARK: - GeoIPDatabasesSheetPresenter

/// Presents ``GeoIPDatabasesSheet`` on the workspace window with
/// `NSWindow.beginSheet`; menu commands have no view to hang a sheet on.
@MainActor
enum GeoIPDatabasesSheetPresenter {
    // MARK: Internal

    static func present(controller: GeoIPController, colorScheme: ColorScheme?) {
        guard presented == nil else {
            presented?.makeKeyAndOrderFront(nil)
            return
        }
        var sheetWindow: NSWindow?
        let close: () -> Void = {
            guard let sheet = sheetWindow else {
                return
            }
            if let host = sheet.sheetParent {
                host.endSheet(sheet)
            } else {
                sheet.orderOut(nil)
            }
            sheetWindow = nil
            presented = nil
        }
        let content = GeoIPDatabasesSheet(controller: controller, onDone: close)
            .preferredColorScheme(colorScheme)
        let sheet = NSWindow(contentViewController: NSHostingController(rootView: content))
        sheet.styleMask = [.titled]
        sheet.title = String(localized: "GeoIP Databases")
        sheet.isReleasedWhenClosed = false
        sheetWindow = sheet
        presented = sheet
        if let parent = hostWindow() {
            parent.beginSheet(sheet)
        } else {
            sheet.center()
            sheet.makeKeyAndOrderFront(nil)
        }
    }

    // MARK: Private

    private static var presented: NSWindow?

    private static func hostWindow() -> NSWindow? {
        let visible = NSApp.windows.filter { $0.isVisible && $0.sheetParent == nil && !($0 is NSPanel) }
        return visible.first { $0.toolbar?.identifier == NativeWorkspaceToolbar.toolbarIdentifier }
            ?? NSApp.mainWindow
            ?? visible.first { $0.canBecomeMain }
    }
}

// MARK: - GeoIPDatabasesMenuItem

/// Statistics ▸ GeoIP Databases…: the active Project's databases.
struct GeoIPDatabasesMenuItem: View {
    let controller: GeoIPController

    var body: some View {
        Button("GeoIP Databases…") {
            controller.presentDatabasesSheet()
        }
    }
}

// MARK: - GeoIPWindowSupport

/// Connects the GeoIP controller to the workspace: the active Project's databases,
/// the `$geoip_…` macros on the Session Expression path, and re-evaluating
/// accepted expressions when the databases change.
struct GeoIPWindowSupport: ViewModifier {
    let coordinator: MainContentCoordinator
    let controller: GeoIPController
    let applicationDefaults: UserDefaults

    func body(content: Content) -> some View {
        content
            .onAppear {
                AddressLocators.installed = controller
                coordinator.filterLibrary.builtInSource = controller
                controller.attach(coordinator, applicationDefaults: applicationDefaults)
            }
            .onChange(of: coordinator.projectStore.activeProjectID) {
                controller.syncProject()
            }
            .onChange(of: coordinator.hasHydratedProjects) {
                controller.syncProject()
            }
            .onChange(of: controller.generation) {
                coordinator.refreshActiveInvestigationQueries()
            }
    }
}

extension View {
    /// The GeoIP support; see ``GeoIPWindowSupport``.
    func geoIPSupport(
        coordinator: MainContentCoordinator,
        controller: GeoIPController,
        applicationDefaults: UserDefaults
    )
        -> some View
    {
        modifier(GeoIPWindowSupport(
            coordinator: coordinator,
            controller: controller,
            applicationDefaults: applicationDefaults
        ))
    }
}
