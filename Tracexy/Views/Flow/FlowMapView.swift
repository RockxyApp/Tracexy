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
        // The map/list split is fixed AppKit content, so it needs explicit room
        // for the outer workspace footer while still rendering beneath its glass.
        .tracexyChromeContentClearance(
            edge: .bottom,
            length: Theme.Metrics.footerBarHeight + Theme.Glass.functionalBarVerticalInset * 2
        )
        .tracexyDenseScrollEdge()
        .tracexySafeAreaBar(edge: .top) { header }
        // Keyed by the set of addresses (plus capture mode), not by bytes or row
        // order, so a saved capture reveals exactly once and a live one re-reveals
        // only when a genuinely new address appears — never on a byte-count tick.
        .task(id: revealSignature) { await revealRoutes() }
    }

    // MARK: Private

    private static let mapMinWidth: CGFloat = 320
    private static let listMinWidth: CGFloat = 260
    private static let listIdealWidth: CGFloat = 320
    private static let listMaxWidth: CGFloat = 460
    /// Points each route is sampled to along its geodesic. Fixed and small: the
    /// reveal advances a prefix of these, so the cost is bounded no matter how far
    /// the destination is.
    private static let routeSampleCount = 20

    /// A user who has asked for less motion gets the finished, static map with no
    /// reveal and no pop.
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// How many sampled points of every route are currently drawn. The routes
    /// reveal outward from the anchor by advancing this prefix exactly once — it
    /// never loops. A saved capture reveals once and stays; a live capture
    /// re-reveals only when the set of addresses changes (see `revealSignature`).
    @State private var visiblePointCount = 2
    /// Drives the single settle pop at the anchor and each marker after a reveal.
    /// A plain 0→1 progress mapped through a sine, so opacity rises and falls once
    /// and ends invisible — a one-shot pop, never a perpetual pulse.
    @State private var pulseProgress: Double = 0
    /// The address selected in the list. Selection lives here rather than in the
    /// workspace: it is a way of reading this surface, not a filter the rest of
    /// the app should inherit.
    @State private var selectedAddress: String?
    /// A region focused by clicking its marker or legend entry. Narrows the list.
    @State private var focusedRegion: EndpointRegion?
    /// Let MapKit fit the anchor and every real registry destination into the
    /// available map pane. User pan/zoom still takes over through this binding.
    @State private var camera: MapCameraPosition = .automatic
    /// Refit only when the set of registry destinations changes. Address growth
    /// inside an existing region can replay the route without stealing a user's
    /// current pan/zoom.
    @State private var fittedRegionSignature = ""

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

    /// The "This Mac" anchor: a fixed, neutral point in the mid-Atlantic that every
    /// route leaves from. Tracexy does not geolocate this device, so this is
    /// deliberately *not* a position — a mid-ocean placeholder is chosen precisely
    /// because it cannot be read as a city, and the legend and its help say so.
    /// Keeping it constant is also what lets a saved capture reveal identically
    /// every time.
    private var origin: CLLocationCoordinate2D {
        CLLocationCoordinate2D(latitude: 32, longitude: -40)
    }

    /// Stable key for the reveal. Built from the set of mappable addresses (sorted,
    /// so order is irrelevant) plus the capture mode — never from bytes — so a live
    /// capture re-reveals when a new address appears but sits still as existing
    /// conversations grow, and a saved capture reveals exactly once.
    private var revealSignature: String {
        let addresses = endpoints
            .filter(\.isMappable)
            .map(\.address)
            .sorted()
            .joined(separator: ",")
        return "\(coordinator.isCapturing ? "live" : "saved")|\(addresses)"
    }

    private var regionSignature: String {
        routes
            .map(\.region.rawValue)
            .sorted()
            .joined(separator: ",")
    }

    /// Each drawn route, its destination geodesic sampled to a fixed number of
    /// points once. The reveal draws a growing prefix of `points`; the last point
    /// is the region-centre marker.
    private var sampledRoutes: [SampledRoute] {
        let start = origin
        return routes.map { route in
            let point = route.region.coordinate
            let destination = CLLocationCoordinate2D(latitude: point.latitude, longitude: point.longitude)
            return SampledRoute(
                region: route.region,
                bytes: route.bytes,
                sessions: route.sessions,
                points: Self.geodesicSamples(from: start, to: destination, count: Self.routeSampleCount)
            )
        }
    }

    /// Sine-shaped 0→1→0 envelope for the settle pop, driven by `pulseProgress`.
    /// Rises then falls across a single reveal and ends invisible, so nothing
    /// pulses forever.
    private var pulseEnvelope: Double {
        sin(min(max(pulseProgress, 0), 1) * .pi)
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
                .font(Theme.Typography.title)
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
            Annotation("This Mac", coordinate: origin) {
                thisMacAnchor
            }

            ForEach(sampledRoutes) { route in
                // A growing prefix of the sampled geodesic — the route drawing
                // outward from the anchor. Always at least two points so a stub is
                // visible from the first frame.
                let count = max(2, min(visiblePointCount, route.points.count))
                MapPolyline(coordinates: Array(route.points.prefix(count)))
                    .stroke(
                        Theme.color(for: route.region).opacity(strokeOpacity(for: route.region)),
                        style: StrokeStyle(lineWidth: weight(for: route.bytes), lineCap: .round)
                    )

                if let destination = route.points.last {
                    let isRevealed = visiblePointCount >= route.points.count
                    Annotation(route.region.title, coordinate: destination) {
                        marker(for: route)
                            // Keep the annotation in MapKit's content bounds from
                            // frame one so `.automatic` can fit every destination,
                            // but do not visually or interactively expose it until
                            // the route actually arrives.
                            .opacity(isRevealed ? 1 : 0)
                            .scaleEffect(isRevealed ? 1 : 0.72)
                            .allowsHitTesting(isRevealed)
                            .accessibilityHidden(!isRevealed)
                    }
                }
            }
        }
        .mapStyle(.standard(elevation: .flat, pointsOfInterest: .excludingAll))
        .mapControlVisibility(.hidden)
    }

    /// The "This Mac" anchor. A laptop glyph on a neutral disc, with a one-shot
    /// pop after the routes land. Labelled everywhere as a *visual* anchor, never
    /// as this device's location — Tracexy ships no geolocation of its own egress.
    private var thisMacAnchor: some View {
        ZStack {
            Circle()
                .stroke(Color.secondary.opacity(pulseEnvelope * 0.5), lineWidth: 1)
                .frame(width: 26, height: 26)
                .scaleEffect(1 + pulseEnvelope * 0.9)
            Circle()
                .fill(.regularMaterial)
                .frame(width: 22, height: 22)
                .overlay(Circle().stroke(Color.secondary.opacity(0.55), lineWidth: 1))
            Image(systemName: "laptopcomputer")
                .font(.system(size: Theme.Icon.small))
                .foregroundStyle(.secondary)
                .scaleEffect(1 + pulseEnvelope * 0.12)
        }
        .accessibilityLabel("This Mac — visual anchor")
        .accessibilityHint("A fixed visual starting point for the route lines, not this device's location.")
        .help("This Mac — a fixed visual anchor for the routes, not this device's location. "
            + "Tracexy does not geolocate your Mac.")
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
            Text("Lines link a neutral “This Mac” anchor to the centre of each registry region "
                + "administering an address block (ARIN, RIPE, APNIC, LACNIC, AFRINIC). The anchor is a "
                + "fixed visual starting point, not this device's location; the lines show reach and "
                + "concentration, not geographic server locations, network paths, or direction.")
                .font(Theme.Typography.micro)
                .foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
        .tracexyContentSurface(
            in: RoundedRectangle(
                cornerRadius: Theme.Metrics.cornerRadius,
                style: .continuous
            )
        )
        .padding(Theme.Glass.functionalBarVerticalInset)
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

    /// A disc sized by volume, marking where a route lands. After the route
    /// reaches it, a single ring pops out once and settles — there is no perpetual
    /// pulse, so a saved capture is fully static and a live one only re-pops when
    /// the set of addresses changes.
    private func marker(for route: SampledRoute) -> some View {
        let tint = Theme.color(for: route.region)
        let size = 12 + 20 * (Double(route.bytes) / Double(maxBytes))
        let isFocused = focusedRegion == route.region
        return ZStack {
            // One-shot settle pop. `pulseEnvelope` is 0 at rest, so this ring is
            // invisible except during the brief pop after a reveal.
            Circle()
                .fill(tint.opacity(pulseEnvelope * 0.32))
                .frame(width: size * 2, height: size * 2)
                .scaleEffect(0.6 + pulseEnvelope * 0.9)
            Circle()
                .fill(tint)
                .frame(width: size, height: size)
                .scaleEffect(1 + pulseEnvelope * 0.12)
                .overlay(
                    Circle()
                        .stroke(isFocused ? Color.primary : .white.opacity(0.85), lineWidth: isFocused ? 2 : 1)
                )
        }
        .opacity(focusedRegion == nil || isFocused ? 1 : 0.45)
        .contentShape(Circle())
        .onTapGesture { toggleFocus(route.region) }
        .accessibilityLabel("\(route.region.title) registry region")
        .accessibilityHint("Registry region administering these addresses, not a server location. "
            + "\(route.sessions) sessions.")
        .help("\(route.region.title) — \(route.sessions) sessions, \(Self.bytes(route.bytes)). "
            + "Registry region, not a server location. Click to filter the list.")
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
            .tracexyGlassButtonStyle()
            .controlSize(.small)
            .padding(.top, 2)
        }
        .padding(.horizontal, Theme.Metrics.spacingL)
        .padding(.vertical, Theme.Metrics.spacingM)
        .frame(maxWidth: .infinity, alignment: .leading)
        .tracexyContentSurface(
            in: RoundedRectangle(cornerRadius: Theme.Metrics.cornerRadius, style: .continuous)
        )
        .padding(Theme.Glass.functionalBarVerticalInset)
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

    /// Samples the geodesic between two points into a fixed number of coordinates,
    /// so a drawn `MapPolyline` follows the globe's curve rather than cutting a
    /// flat straight line across the projection.
    ///
    /// Pure and bounded: it builds one `MKGeodesicPolyline`, then resamples its
    /// own densified point list down to exactly `count` evenly spaced coordinates.
    /// No state, no allocation beyond the returned array — safe to call from the
    /// view body.
    private static func geodesicSamples(
        from start: CLLocationCoordinate2D,
        to end: CLLocationCoordinate2D,
        count: Int
    )
        -> [CLLocationCoordinate2D]
    {
        guard count > 1 else {
            return [start, end]
        }
        let polyline = MKGeodesicPolyline(coordinates: [start, end], count: 2)
        let sourceCount = polyline.pointCount
        guard sourceCount > 1 else {
            return [start, end]
        }
        let points = polyline.points()
        var result: [CLLocationCoordinate2D] = []
        result.reserveCapacity(count)
        for index in 0 ..< count {
            let position = Double(index) / Double(count - 1) * Double(sourceCount - 1)
            let clamped = Int(min(max(position, 0), Double(sourceCount - 1)).rounded())
            result.append(points[clamped].coordinate)
        }
        return result
    }

    /// Advances the route reveal once, then fires a single settle pop.
    ///
    /// This is deliberately a bounded loop, not a `TimelineView` or a
    /// `repeatForever` animation: it draws each route outward from the anchor in
    /// one simultaneous burst over ~0.6 s and then stops. Cancellation (a new
    /// signature, or the view going away) drops out of the sleep and leaves the
    /// next run to reset the state.
    @MainActor
    private func revealRoutes() async {
        guard !routes.isEmpty else {
            visiblePointCount = 2
            pulseProgress = 0
            return
        }
        fitCameraIfNeeded()
        // Reduced motion: no reveal, no pop — the finished map, immediately.
        if reduceMotion {
            visiblePointCount = Self.routeSampleCount
            pulseProgress = 0
            return
        }

        visiblePointCount = 2
        pulseProgress = 0
        let steps = Self.routeSampleCount
        let perStep = UInt64(0.6 / Double(steps - 1) * 1_000_000_000)
        for step in 2 ... steps {
            visiblePointCount = step
            do {
                try await Task.sleep(nanoseconds: perStep)
            } catch {
                return // cancelled — the next run resets the prefix
            }
        }
        visiblePointCount = Self.routeSampleCount

        // One restrained pop at the anchor and each marker, then settle.
        withAnimation(.easeOut(duration: 0.5)) {
            pulseProgress = 1
        }
    }

    /// Explicitly fit every sampled geodesic, not just the currently visible
    /// prefix. MapKit's automatic camera can otherwise lock onto the short first
    /// frame and leave a far registry marker just outside the pane.
    @MainActor
    private func fitCameraIfNeeded() {
        let signature = regionSignature
        guard signature != fittedRegionSignature else {
            return
        }
        let coordinates = [origin] + sampledRoutes.flatMap(\.points)
        guard let first = coordinates.first else {
            return
        }

        let firstPoint = MKMapPoint(first)
        var rect = MKMapRect(x: firstPoint.x, y: firstPoint.y, width: 1, height: 1)
        for coordinate in coordinates.dropFirst() {
            let point = MKMapPoint(coordinate)
            rect = rect.union(MKMapRect(x: point.x, y: point.y, width: 1, height: 1))
        }
        let horizontalPadding = max(rect.size.width * 0.12, 1)
        let verticalPadding = max(rect.size.height * 0.18, 1)
        camera = .rect(rect.insetBy(dx: -horizontalPadding, dy: -verticalPadding))
        fittedRegionSignature = signature
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

// MARK: - SampledRoute

/// One drawn route: a region destination whose geodesic from the anchor has been
/// sampled to a fixed list of points, so the reveal can grow a prefix of them.
private struct SampledRoute: Identifiable {
    let region: EndpointRegion
    let bytes: Int
    let sessions: Int
    let points: [CLLocationCoordinate2D]

    var id: EndpointRegion {
        region
    }
}
