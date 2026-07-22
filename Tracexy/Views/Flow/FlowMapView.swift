import AppKit
import MapKit
import SwiftUI

// MARK: - FlowMapView

/// Where this Mac's traffic is going — a registry map beside the list of actual
/// addresses behind it.
///
/// **What this map does and does not claim.** Tracexy ships no geolocation
/// database, so it does not know where a server physically is. What it can
/// resolve offline is which Regional Internet Registry administers an address
/// block, which is a real and checkable fact. Every marker is therefore placed
/// at the centre of a *registry region*, and the map says so. A registry is not
/// a location — an ARIN block can be announced from anywhere — and drawing a
/// precise pin from an imprecise fact would be the kind of confident lie the
/// rest of this app refuses to tell.
///
/// **Why there is a list.** A map of five registry regions is, by construction,
/// the coarsest view of a capture the app can draw — and it was the *only* view
/// this surface offered, which made it decorative. The question that brings
/// someone here is "which address is my app actually talking to", and a marker
/// covering a third of a continent cannot answer it. So the map keeps the job it
/// can do honestly — showing concentration and reach — and hands the precise job
/// to a list of real addresses beside it. Selecting on either side drives the
/// other, and a row opens straight into a filtered session list.
///
/// The list is also what makes this surface work when the map cannot. Traffic
/// that never left the LAN has no registry region, so it draws nothing; those
/// endpoints still appear in the list, marked unmappable, instead of the surface
/// reading as broken.
///
/// MapKit supplies the coastlines, so no map data is bundled and the rendering
/// stays native.
struct FlowMapView: View {
    // MARK: Internal

    var coordinator: MainContentCoordinator

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            HSplitView {
                mapSide
                    .frame(minWidth: Self.mapMinWidth, maxWidth: .infinity, maxHeight: .infinity)
                endpointList
                    .frame(
                        minWidth: Self.listMinWidth,
                        idealWidth: Self.listIdealWidth,
                        maxWidth: Self.listMaxWidth,
                        maxHeight: .infinity
                    )
            }
            .id("tracexy-flow-split")
        }
        .onAppear { animate = true }
    }

    // MARK: Private

    private static let mapMinWidth: CGFloat = 320
    private static let listMinWidth: CGFloat = 260
    private static let listIdealWidth: CGFloat = 320
    private static let listMaxWidth: CGFloat = 460

    /// Drives the pulse travelling along each route. A single shared phase keeps
    /// every route in step and costs one animation, not one per route.
    @State private var animate = false
    /// The address selected in the list. Selection lives here rather than in the
    /// workspace: it is a way of reading this surface, not a filter the rest of
    /// the app should inherit.
    @State private var selectedAddress: String?
    /// A region focused by clicking its marker or legend entry. Narrows the list.
    @State private var focusedRegion: EndpointRegion?
    @State private var camera: MapCameraPosition = .region(
        MKCoordinateRegion(
            center: CLLocationCoordinate2D(latitude: 25, longitude: 0),
            span: MKCoordinateSpan(latitudeDelta: 130, longitudeDelta: 340)
        )
    )

    private var endpoints: [FlowEndpoint] {
        coordinator.flowEndpoints
    }

    /// Rows after any marker focus — the map narrowing the list is the whole
    /// point of having both side by side.
    private var listedEndpoints: [FlowEndpoint] {
        guard let focusedRegion else {
            return endpoints
        }
        return endpoints.filter { $0.region == focusedRegion }
    }

    private var selectedEndpoint: FlowEndpoint? {
        endpoints.first { $0.address == selectedAddress }
    }

    /// Regions carrying traffic that actually left this network. `.local` is
    /// excluded — it has no place on a world map, and drawing it at 0,0 would
    /// put private traffic in the Gulf of Guinea.
    private var routes: [(region: EndpointRegion, bytes: Int, sessions: Int)] {
        coordinator.regionTraffic.filter { $0.region != .local && $0.region != .unknown }
    }

    private var unmappableCount: Int {
        endpoints.count { !$0.isMappable }
    }

    private var maxBytes: Int {
        max(routes.map(\.bytes).max() ?? 1, 1)
    }

    private var origin: CLLocationCoordinate2D {
        // The capturing Mac. Without geolocation of our own egress we cannot
        // place it either, so it sits at the centre of the region administering
        // whichever addresses we are talking to most — and the legend says the
        // map is regional, not positional.
        let busiest = routes.last?.region ?? .northAmerica
        let point = busiest.coordinate
        return CLLocationCoordinate2D(latitude: point.latitude, longitude: point.longitude)
    }

    private var mapEmptyReason: String {
        if coordinator.visibleSessions.isEmpty {
            return "Start a capture to see where traffic is going."
        }
        if unmappableCount > 0 {
            return "All \(unmappableCount) addresses so far are private, loopback or unallocated — "
                + "they have no registry region to place. They are listed on the right."
        }
        return "Everything captured so far stayed on the local network."
    }

    private var header: some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Label("Flow", systemImage: "globe.americas")
                .font(Theme.Typography.surfaceTitle)
            Text("\(endpoints.count) addresses · \(routes.count) regions")
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
            Spacer(minLength: Theme.Metrics.spacingM)
            if let focusedRegion {
                Button {
                    clearFocus()
                } label: {
                    Label("\(focusedRegion.title) only", systemImage: "xmark.circle.fill")
                        .font(Theme.Typography.caption)
                }
                .buttonStyle(.borderless)
                .help("Clear the region focus and list every address again")
            }
        }
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    // MARK: Map side

    private var mapSide: some View {
        VStack(spacing: 0) {
            if routes.isEmpty {
                mapEmpty
            } else {
                map
            }
            Divider()
            legend
        }
    }

    private var map: some View {
        Map(position: $camera, interactionModes: [.pan, .zoom]) {
            ForEach(routes, id: \.region) { route in
                let point = route.region.coordinate
                let destination = CLLocationCoordinate2D(latitude: point.latitude, longitude: point.longitude)

                MapPolyline(coordinates: [origin, destination])
                    .stroke(
                        Theme.color(for: route.region).opacity(strokeOpacity(for: route.region)),
                        style: StrokeStyle(lineWidth: weight(for: route.bytes), lineCap: .round)
                    )

                Annotation(route.region.title, coordinate: destination) {
                    marker(for: route)
                }
            }
        }
        .mapStyle(.standard(elevation: .flat, pointsOfInterest: .excludingAll))
        .mapControlVisibility(.hidden)
    }

    /// The map's own empty state, which names the reason instead of saying "no
    /// data". With a capture running, an empty map almost always means the
    /// traffic stayed local — and that is a finding, not a failure.
    private var mapEmpty: some View {
        VStack(spacing: Theme.Metrics.spacingM) {
            Spacer()
            Image(systemName: "globe.americas")
                .font(.system(size: Theme.Icon.hero))
                .foregroundStyle(.tertiary)
            Text("Nothing routed yet")
                .font(Theme.Typography.surfaceTitle)
            Text(mapEmptyReason)
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, Theme.Metrics.spacingL)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var legend: some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            if !routes.isEmpty {
                HStack(spacing: Theme.Metrics.spacingL) {
                    ForEach(routes.reversed(), id: \.region) { route in
                        Button {
                            toggleFocus(route.region)
                        } label: {
                            HStack(spacing: 5) {
                                StatusDot(Theme.color(for: route.region))
                                Text(route.region.title)
                                    .font(Theme.Typography.caption)
                                Text(Self.bytes(route.bytes))
                                    .font(Theme.Typography.caption)
                                    .monospacedDigit()
                                    .foregroundStyle(.secondary)
                            }
                            .opacity(focusedRegion == nil || focusedRegion == route.region ? 1 : 0.4)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .help("Show only \(route.region.title) addresses")
                    }
                    Spacer(minLength: 0)
                }
            }
            Text("Markers sit at the centre of the registry region administering each address block "
                + "(ARIN, RIPE, APNIC, LACNIC, AFRINIC). A registry is not a location — this map shows "
                + "who administers the address, not where the server is.")
                .font(Theme.Typography.micro)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
    }

    // MARK: List side

    private var endpointList: some View {
        VStack(spacing: 0) {
            SectionHeader(
                focusedRegion?.title ?? "Addresses",
                detail: "\(listedEndpoints.count)"
            )
            .padding(.horizontal, Theme.Metrics.spacingL)
            .padding(.vertical, Theme.Metrics.spacingM)
            Divider()
            if listedEndpoints.isEmpty {
                listEmpty
            } else {
                List(listedEndpoints, selection: $selectedAddress) { endpoint in
                    endpointRow(endpoint)
                        .tag(endpoint.address)
                        .contextMenu { rowMenu(endpoint) }
                }
                .listStyle(.inset)
            }
            if let selectedEndpoint {
                Divider()
                detail(for: selectedEndpoint)
            }
        }
        .background(.background)
    }

    private var listEmpty: some View {
        VStack(spacing: Theme.Metrics.spacingM) {
            Spacer()
            Text(coordinator.visibleSessions.isEmpty
                ? "No traffic captured yet."
                : "No addresses in this region.")
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// A pulsing disc sized by volume. The pulse is what makes a live capture
    /// legible at a glance — a still map cannot distinguish traffic now from
    /// traffic ten minutes ago.
    private func marker(for route: (region: EndpointRegion, bytes: Int, sessions: Int)) -> some View {
        let tint = Theme.color(for: route.region)
        let size = 12 + 20 * (Double(route.bytes) / Double(maxBytes))
        let isFocused = focusedRegion == route.region
        return ZStack {
            Circle()
                .fill(tint.opacity(0.22))
                .frame(width: size * 2, height: size * 2)
                .scaleEffect(animate ? 1.0 : 0.55)
                .opacity(animate ? 0 : 0.8)
                .animation(
                    .easeOut(duration: 1.8).repeatForever(autoreverses: false),
                    value: animate
                )
            Circle()
                .fill(tint)
                .frame(width: size, height: size)
                .overlay(
                    Circle()
                        .stroke(isFocused ? Color.primary : .white.opacity(0.85), lineWidth: isFocused ? 2 : 1)
                )
        }
        .opacity(focusedRegion == nil || isFocused ? 1 : 0.45)
        .contentShape(Circle())
        .onTapGesture { toggleFocus(route.region) }
        .help("\(route.region.title) — \(route.sessions) sessions, \(Self.bytes(route.bytes)). "
            + "Click to filter the list.")
    }

    private func endpointRow(_ endpoint: FlowEndpoint) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            // The region tint is the row's link to the map — same colour and the
            // same key as the legend, so a row and its marker read as one thing.
            StatusDot(Theme.color(for: endpoint.region))
            VStack(alignment: .leading, spacing: 1) {
                Text(endpoint.displayName)
                    .font(Theme.Typography.body)
                    .lineLimit(1)
                    .truncationMode(.middle)
                // The address shows even when a name led the row: it is the
                // precise fact this surface exists to give, so it is never
                // hidden behind the friendlier label.
                Text(endpoint.address)
                    .font(Theme.Typography.monoMicro)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer(minLength: Theme.Metrics.spacingM)
            VStack(alignment: .trailing, spacing: 1) {
                Text(Self.bytes(endpoint.bytes))
                    .font(Theme.Typography.caption)
                    .monospacedDigit()
                Text("\(endpoint.sessionCount)")
                    .font(Theme.Typography.micro)
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
            }
            if endpoint.status != .ok {
                Image(systemName: endpoint.status.systemImage)
                    .font(.system(size: Theme.Icon.small))
                    .foregroundStyle(Theme.color(for: endpoint.status))
                    .help(endpoint.status.label)
            }
        }
        .padding(.vertical, 2)
    }

    /// The selected address, spelled out under the list.
    ///
    /// The row is deliberately terse — it has to stay scannable at 260 pt — so
    /// the facts that only matter once you have picked something (every name the
    /// address answered to, its registry, whether it can be mapped at all) live
    /// here instead of crowding every row.
    private func detail(for endpoint: FlowEndpoint) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            Text(endpoint.address)
                .font(Theme.Typography.mono)
                .textSelection(.enabled)
                .lineLimit(1)
                .truncationMode(.middle)

            if endpoint.names.count > 1 {
                // Several names on one address is normal behind a CDN, and it is
                // exactly what a single-name row would hide.
                Text("Also answered to \(endpoint.names.dropFirst().joined(separator: ", "))")
                    .font(Theme.Typography.micro)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack(spacing: Theme.Metrics.spacingM) {
                Text(endpoint.region.title)
                    .font(Theme.Typography.micro)
                    .foregroundStyle(.secondary)
                if let registry = endpoint.region.registry {
                    Text(registry)
                        .font(Theme.Typography.badge)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(Capsule().fill(Theme.color(for: endpoint.region).opacity(0.15)))
                        .foregroundStyle(Theme.color(for: endpoint.region))
                }
                Spacer(minLength: 0)
            }

            if !endpoint.isMappable {
                Label("Not on the map — no registry region", systemImage: "mappin.slash")
                    .font(Theme.Typography.micro)
                    .foregroundStyle(.tertiary)
            }

            Button {
                coordinator.selectIP(endpoint.address)
            } label: {
                Label("Show \(endpoint.sessionCount) sessions", systemImage: "arrow.right.circle")
                    .font(Theme.Typography.caption)
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .padding(.top, 2)
        }
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.secondary)
    }

    @ViewBuilder
    private func rowMenu(_ endpoint: FlowEndpoint) -> some View {
        Button("Show Sessions", systemImage: "arrow.right.circle") {
            coordinator.selectIP(endpoint.address)
        }
        if let name = endpoint.names.first {
            Button("Show Everything for \(name)", systemImage: "globe") {
                coordinator.selectHost(name)
            }
        }
        Divider()
        Button("Copy Address", systemImage: "doc.on.doc") {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(endpoint.address, forType: .string)
        }
    }

    private static func bytes(_ count: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(count), countStyle: .binary)
    }

    // MARK: Behaviour

    /// Clicking a marker or a legend entry focuses that region; clicking the
    /// focused one again clears it. A toggle rather than a mode, so there is no
    /// state the user can get stuck in without an obvious way out.
    private func toggleFocus(_ region: EndpointRegion) {
        let next: EndpointRegion? = (focusedRegion == region) ? nil : region
        withAnimation(.smooth(duration: 0.2)) {
            focusedRegion = next
        }
        // A selection from another region would sit under a filter that hides
        // it, so it is dropped rather than left silently applied.
        if let next, selectedEndpoint?.region != next {
            selectedAddress = nil
        }
    }

    private func clearFocus() {
        withAnimation(.smooth(duration: 0.2)) {
            focusedRegion = nil
        }
    }

    private func strokeOpacity(for region: EndpointRegion) -> Double {
        guard let focusedRegion else {
            return 0.55
        }
        return focusedRegion == region ? 0.85 : 0.15
    }

    private func weight(for bytes: Int) -> Double {
        1 + 4 * (Double(bytes) / Double(maxBytes))
    }
}
