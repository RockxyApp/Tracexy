import SwiftUI

/// Present lifecycle prompts from the frontmost Project surface, including the
/// manager sheet. The action retains the presented request across dismissal.
struct ProjectTransitionPresentation: ViewModifier {
    let coordinator: MainContentCoordinator
    var isActive = true

    func body(content: Content) -> some View {
        content
            .confirmationDialog(
                "Stop the capture and change Projects?",
                isPresented: Binding(
                    get: { isActive && coordinator.pendingProjectSwitchConfirmation != nil },
                    set: {
                        if !$0 {
                            coordinator.cancelPendingProjectSwitch()
                        }
                    }
                ),
                titleVisibility: .visible,
                presenting: coordinator.pendingProjectSwitchConfirmation
            ) { request in
                Button("Stop and Switch") {
                    // SwiftUI may dismiss the presentation binding before the
                    // action fires. Keep the immutable request shown to the user.
                    coordinator.pendingProjectSwitchConfirmation = request
                    coordinator.confirmPendingProjectSwitch()
                }
                Button("Cancel", role: .cancel) { coordinator.cancelPendingProjectSwitch() }
            } message: { request in
                Text(
                    "“\(request.outgoingProjectName)” is capturing. Tracexy will stop it, wait for the "
                        + "final packets and its History entry, then open “\(request.destinationDescription)”. "
                        + "Switching preserves its captured data. Deleting a Project discards its unsaved sessions."
                )
            }
            .alert(
                "Project Change Didn’t Finish",
                isPresented: Binding(
                    get: { isActive && coordinator.projectTransitionStatus.failureMessage != nil },
                    set: { _ in }
                )
            ) {
                if coordinator.retryableProjectTransition != nil {
                    Button("Try Again") { coordinator.retryProjectTransition() }
                }
                Button("Stay Here", role: .cancel) { coordinator.dismissProjectTransitionFailure() }
            } message: {
                Text(coordinator.projectTransitionStatus.failureMessage ?? "")
            }
    }
}
