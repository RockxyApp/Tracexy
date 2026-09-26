import Foundation
import SwiftUI

// The app binary doubles as the read-only `tracexy` command line. A first argument
// naming one of its commands runs it and exits before any window, Project or
// capture machinery starts; every other launch is the normal app.
if let status = TracexyCommandLine.runIfRequested(CommandLine.arguments) {
    exit(status)
}

TracexyApp.main()
