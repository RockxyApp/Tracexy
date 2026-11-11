import AppKit
import MapKit
import SwiftUI

// MARK: - FlowMapView

/// Where the captured traffic was addressed — a registry overview beside the
/// list of actual destination addresses behind it.
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
/// It makes no claim about the *source* either. A capture can be an imported
/// file recorded on another machine entirely, so the routes leave a neutral
/// capture anchor rather than anything that reads as this device.
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
        let projection = FlowMapProjection(
            sessions: coordinator.visibleSessions,
            isCapturing: coordinator.isCapturing
        )
        return HSplitView {
            mapSide(projection: projection)
                .frame(minWidth: Self.mapMinWidth, maxWidth: .infinity, maxHeight: .infinity)
            endpointList(projection: projection)
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
        .tracexySafeAreaBar(edge: .top) { topBar(projection: projection) }
    }

    // MARK: Private

    private static let mapMinWidth: CGFloat = 320
    private static let listMinWidth: CGFloat = 260
    private static let listIdealWidth: CGFloat = 320
    private static let listMaxWidth: CGFloat = 460
    /// The address selected in the list. Selection lives here rather than in the
    /// workspace: it is a way of reading this surface, not a filter the rest of
    /// the app should inherit.
    @State private var selectedAddress: String?
    /// A region focused by clicking its marker or legend entry. Narrows the list.
    @State private var focusedRegion: EndpointRegion?

    /// The existing header plus the shared scope line. Flow draws the same
    /// filtered session set as the table, so it says so in the same words — and,
    /// having no filter shelf of its own, carries the same single reset route.
    private func topBar(projection: FlowMapProjection) -> some View {
        // The scope is read here so the line's own padding is added only when
        // there is a line; an empty notice must not reserve height in the bar.
        let scope = coordinator.sessionScope(shownCount: projection.visibleSessionCount)
        return VStack(alignment: .leading, spacing: 0) {
            header(projection: projection)
            if scope.isConstrained || coordinator.canReturnToPreviousSessionScope {
                SessionScopeNotice(
                    coordinator: coordinator,
                    shownCount: projection.visibleSessionCount,
                    showsResetAction: true
                )
                .padding(.horizontal, Theme.Metrics.spacingL)
                .padding(.bottom, Theme.Metrics.spacingM)
            }
        }
    }

    private func header(projection: FlowMapProjection) -> some View {
        HStack(spacing: Theme.Metrics.spacingM) {
            Label("Flow", systemImage: "globe.americas")
                .font(Theme.Typography.title)
            Text("\(projection.endpoints.count) addresses in \(projection.routes.count) regions")
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

    private func mapSide(projection: FlowMapProjection) -> some View {
        VStack(spacing: 0) {
            FlowMapCanvas(
                projection: projection,
                hasCapturedSessions: !coordinator.sessions.isEmpty,
                focusedRegion: $focusedRegion,
                onToggleFocus: { toggleFocus($0, projection: projection) }
            )
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            Divider()
            legend(projection: projection)
        }
    }

    private func legend(projection: FlowMapProjection) -> some View {
        VStack(alignment: .leading, spacing: Theme.Metrics.spacingS) {
            if !projection.routes.isEmpty {
                HStack(spacing: Theme.Metrics.spacingL) {
                    ForEach(projection.routes.reversed(), id: \.region) { route in
                        Button {
                            toggleFocus(route.region, projection: projection)
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
            Text("Destination addresses grouped by registry region. Map positions indicate address "
                + "administration, not server locations; the capture origin is not shown.")
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

    private func endpointList(projection: FlowMapProjection) -> some View {
        let listedEndpoints = focusedRegion.map { region in
            projection.endpoints.filter { $0.region == region }
        } ?? projection.endpoints
        let selectedEndpoint = projection.endpoints.first { $0.address == selectedAddress }
        return VStack(spacing: 0) {
            SectionHeader(
                focusedRegion?.title ?? "Addresses",
                detail: "\(listedEndpoints.count)"
            )
            .padding(.horizontal, Theme.Metrics.spacingL)
            .padding(.vertical, Theme.Metrics.spacingM)
            if projection.omittedSessionCount > 0 {
                // Rows are grouped by the typed destination address. A session
                // the fold could not give one to belongs in no row, and saying
                // how many is the difference between a bounded list and a list
                // that quietly describes less than the surface claims.
                Text("\(projection.omittedSessionCount.formatted()) session"
                    + "\(projection.omittedSessionCount == 1 ? "" : "s") not listed — no destination address decoded.")
                    .font(Theme.Typography.micro)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, Theme.Metrics.spacingL)
                    .padding(.bottom, Theme.Metrics.spacingM)
                    .accessibilityIdentifier("flow-endpoints-omitted-notice")
            }
            Divider()
            if listedEndpoints.isEmpty {
                listEmpty(projection: projection)
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

    private func listEmpty(projection: FlowMapProjection) -> some View {
        VStack(spacing: Theme.Metrics.spacingM) {
            Spacer()
            Text(projection.visibleSessionCount == 0
                ?
                (coordinator.sessions
                    .isEmpty ? "No sessions in this capture." : "No addresses match the current scope.")
                : "No addresses in this region.")
                .font(Theme.Typography.caption)
                .foregroundStyle(.secondary)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
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
                // The destination-only drill-in, matching exactly the fact this
                // row is grouped by, so the list it opens is the count above it.
                coordinator.showSessionsForAggregateDestination(endpoint.address)
            } label: {
                Label("Show \(endpoint.sessionCount) sessions", systemImage: "arrow.right.circle")
                    .font(Theme.Typography.caption)
                    .frame(maxWidth: .infinity)
            }
            .tracexyGlassButtonStyle()
            .controlSize(.small)
            .disabled(isStaleDestination(endpoint))
            .help(isStaleDestination(endpoint)
                ? "The session list is already scoped to another destination address."
                : "Narrow the current scope to sessions sent to \(endpoint.address)")
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
            coordinator.showSessionsForAggregateDestination(endpoint.address)
        }
        .disabled(isStaleDestination(endpoint))
        if let name = endpoint.names.first {
            // Opens the global host scope while retaining search and category filters.
            Button("Show Sessions for \(name)", systemImage: "globe") {
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
        ByteUnits.string(Int64(count))
    }

    /// Whether this row can no longer narrow anything, because the list is
    /// already scoped to a different destination. Such a click is a no-op rather
    /// than a replacement — swapping the address would widen past the row that
    /// produced the current scope.
    private func isStaleDestination(_ endpoint: FlowEndpoint) -> Bool {
        guard let current = coordinator.activeWorkspace.aggregateDestinationFilter else {
            return false
        }
        return IPAddressValue(parsing: current) != IPAddressValue(parsing: endpoint.address)
    }

    // MARK: Behaviour

    /// Clicking a marker or a legend entry focuses that region; clicking the
    /// focused one again clears it. A toggle rather than a mode, so there is no
    /// state the user can get stuck in without an obvious way out.
    private func toggleFocus(_ region: EndpointRegion, projection: FlowMapProjection) {
        let next: EndpointRegion? = (focusedRegion == region) ? nil : region
        withAnimation(.smooth(duration: 0.2)) {
            focusedRegion = next
        }
        // A selection from another region would sit under a filter that hides
        // it, so it is dropped rather than left silently applied.
        let selectedEndpoint = projection.endpoints.first { $0.address == selectedAddress }
        if let next, selectedEndpoint?.region != next {
            selectedAddress = nil
        }
    }

    private func clearFocus() {
        withAnimation(.smooth(duration: 0.2)) {
            focusedRegion = nil
        }
    }
}

// MARK: - FlowMapCanvas

/// Owns the map's reveal animation so its frequent state updates do not rebuild
/// the parent FlowMap projection from every visible session.
private struct FlowMapCanvas: View {
    let projection: FlowMapProjection
    let hasCapturedSessions: Bool
    @Binding var focusedRegion: EndpointRegion?
    let onToggleFocus: (EndpointRegion) -> Void

    // MARK: Internal

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var visiblePointCount = 2
    @State private var pulseProgress: Double = 0
    /// MapKit pan/zoom state stays inside the canvas, so changing it cannot rebuild
    /// the parent FlowMap projection.
    @State private var camera: MapCameraPosition = .automatic
    @State private var fittedRegionSignature = ""

    private static let routeSampleCount = 20

    var body: some View {
        Group {
            if projection.routes.isEmpty {
                mapEmpty
            } else {
                map
            }
        }
        // Keyed by the same endpoint set used to build this canvas. Animation state
        // changes stay inside this child and never rebuild the parent projection.
        .task(id: projection.revealSignature) { await revealRoutes() }
    }

    // MARK: Private

    private var captureAnchor: CLLocationCoordinate2D {
        CLLocationCoordinate2D(latitude: 32, longitude: -40)
    }

    private var pulseEnvelope: Double {
        sin(min(max(pulseProgress, 0), 1) * .pi)
    }

    private var sampledRoutes: [SampledRoute] {
        let start = captureAnchor
        return projection.routes.map { route in
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

    private var map: some View {
        Map(position: $camera, interactionModes: [.pan, .zoom]) {
            Annotation("Captured traffic", coordinate: captureAnchor) {
                anchorMarker
            }

            ForEach(sampledRoutes) { route in
                // A growing prefix of the sampled geodesic — the route drawing
                // outward from the anchor. Always at least two points so a stub is
                // visible from the first frame.
                let count = max(2, min(visiblePointCount, route.points.count))
                MapPolyline(coordinates: Array(route.points.prefix(count)))
                    .stroke(
                        Theme.color(for: route.region).opacity(strokeOpacity(for: route.region)),
                        style: StrokeStyle(
                            lineWidth: weight(for: route.bytes), lineCap: .round
                        )
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

    /// The capture anchor. A neutral marker disc, with a one-shot pop after the
    /// routes land. It is a drawing convention, never a claim about this Mac's
    /// location or the location where an imported capture was recorded.
    private var anchorMarker: some View {
        ZStack {
            Circle()
                .stroke(Color.secondary.opacity(pulseEnvelope * 0.5), lineWidth: 1)
                .frame(width: 26, height: 26)
                .scaleEffect(1 + pulseEnvelope * 0.9)
            Circle()
                .fill(.regularMaterial)
                .frame(width: 22, height: 22)
                .overlay(Circle().stroke(Color.secondary.opacity(0.55), lineWidth: 1))
            Image(systemName: "smallcircle.filled.circle")
                .font(.system(size: Theme.Icon.small))
                .foregroundStyle(.secondary)
                .scaleEffect(1 + pulseEnvelope * 0.12)
        }
        .accessibilityLabel("Captured traffic")
        .accessibilityHint("Traffic recorded in the current capture. Its origin location is not shown.")
        .help("Traffic recorded in the current capture")
    }

    /// The map's empty state names why no route can be drawn.
    private var mapEmpty: some View {
        let emptyTitle = projection.visibleSessionCount == 0 && hasCapturedSessions
            ? "No Matching Sessions"
            : "No Mappable Addresses"
        VStack(spacing: Theme.Metrics.spacingM) {
            Spacer()
            Image(systemName: "globe.americas")
                .font(.system(size: Theme.Icon.hero))
                .foregroundStyle(.tertiary)
            Text(emptyTitle)
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

    private var mapEmptyReason: String {
        if projection.visibleSessionCount == 0 {
            return hasCapturedSessions
                ? "Sessions exist in this capture, but none match the current scope."
                : "Open or start a capture to inspect its addresses."
        }
        if projection.unmappableCount > 0 {
            return "All \(projection.unmappableCount) addresses so far are private, loopback or unallocated — "
                + "they have no registry region to place. They are listed on the right."
        }
        return "Everything captured so far stayed on the local network."
    }

    /// Advances the route reveal once. Only this canvas updates as the sampled
    /// point prefix grows; the parent FlowMap projection remains unchanged.
    @MainActor
    private func revealRoutes() async {
        guard !projection.routes.isEmpty else {
            visiblePointCount = 2
            pulseProgress = 0
            return
        }
        fitCameraIfNeeded()
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
                return
            }
        }
        visiblePointCount = Self.routeSampleCount
        withAnimation(.easeOut(duration: 0.5)) {
            pulseProgress = 1
        }
    }

    /// Fits the map only when the set of registry destinations changes.
    @MainActor
    private func fitCameraIfNeeded() {
        guard projection.regionSignature != fittedRegionSignature else {
            return
        }
        let coordinates = [captureAnchor] + sampledRoutes.flatMap(\.points)
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
        fittedRegionSignature = projection.regionSignature
    }

    private func marker(for route: SampledRoute) -> some View {
        let tint = Theme.color(for: route.region)
        let size = 12 + 20 * (Double(route.bytes) / Double(projection.maxBytes))
        let isFocused = focusedRegion == route.region
        let hint = [
            "Registry region administering these addresses, not a server location.",
            "\(route.sessions) sessions.",
        ].joined(separator: " ")
        let help = [
            "\(route.region.title) — \(route.sessions) sessions, \(ByteUnits.string(Int64(route.bytes))).",
            "Registry region, not a server location. Click to filter the list.",
        ].joined(separator: " ")
        return ZStack {
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
        .onTapGesture { onToggleFocus(route.region) }
        .accessibilityAddTraits(.isButton)
        .accessibilityAction { onToggleFocus(route.region) }
        .accessibilityLabel("\(route.region.title) registry region")
        .accessibilityHint(hint)
        .help(help)
    }

    private func strokeOpacity(for region: EndpointRegion) -> Double {
        guard let focusedRegion else {
            return 0.55
        }
        return focusedRegion == region ? 0.85 : 0.15
    }

    private func weight(for bytes: Int) -> Double {
        1 + 4 * (Double(bytes) / Double(projection.maxBytes))
    }

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
