import Foundation
import Testing
@testable import Tracexy

@Suite("WorkspaceState defaults")
struct WorkspaceStateTests {
    @Test("A fresh workspace shows raw observed sessions, not inferred actions")
    func defaultsToFlatSessions() {
        let workspace = WorkspaceState(title: "Capture")
        // Action grouping is inference and must be opt-in; the honest default is
        // every observed session, flat.
        #expect(workspace.sessionGrouping == .none)
    }

    @Test("The inferred and observed grouping choices all remain available")
    func groupingChoicesRemainAvailable() {
        // The default changed, but switching to Action/Host/Process must still work.
        let workspace = WorkspaceState(title: "Capture")
        for grouping in SessionGrouping.allCases {
            workspace.sessionGrouping = grouping
            #expect(workspace.sessionGrouping == grouping)
        }
        #expect(SessionGrouping.allCases.contains(.action))
        #expect(SessionGrouping.action.isInferred)
        #expect(!SessionGrouping.host.isInferred)
        #expect(!SessionGrouping.process.isInferred)
        #expect(!SessionGrouping.none.isInferred)
    }
}
