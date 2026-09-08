import Foundation

// MARK: - The exact final boundary a stopped capture owes

/// One stop owes exactly one final drain: the helper's last atomic batch folded,
/// published as the stopped snapshot, and its terminal History write enqueued.
/// Everything that must not run across that boundary — Start, Clear, adopting
/// another capture source, and every Project change — parks on the owed
/// *operation* rather than on a generation token, so a retry issued while the same
/// stop is still draining awaits that same boundary instead of opening a second,
/// independently satisfiable one.
///
/// The operation is retired exactly once, either by the ingest chain's own
/// completion or by a recovery path that terminates it as failed. It is never
/// retired by a timer: a bounded wait that elapses fails its waiter and leaves the
/// operation owed, because "we stopped waiting" is not "the tail arrived".
@MainActor
extension MainContentCoordinator {
    /// True from the moment Stop is issued until this capture's final helper drain,
    /// fold, and terminal publication have completed. The Project lifecycle path
    /// waits on the completion signal rather than polling for it.
    var isFinalDrainPending: Bool {
        owedFinalDrain != nil
    }

    /// The identity of the drain operation currently owed, or `nil` when none is.
    var pendingFinalDrainOperationID: Int? {
        owedFinalDrain?.operationID
    }

    /// Record that a stop owes an exact final drain, and return the identity of the
    /// drain operation now owed.
    ///
    /// A stop still waiting behind an in-flight helper fetch owes a drain before it
    /// has a stopped generation, so `stoppedToken` is `nil` there and is resolved
    /// onto the *same* operation once the stop actually runs. A genuinely new stop
    /// supersedes an unfinished one: its waiters were parked on a boundary that
    /// will never be reached, so they are failed rather than released by the wrong
    /// capture or left to time out.
    ///
    /// The engine epoch this drain belongs to and the Project that owns it are
    /// recorded on the operation itself, so a recovery path can finalize exactly the
    /// capture that owes it instead of deriving one from token arithmetic.
    /// `captureToken` defaults to the current generation, which is the capture epoch
    /// at every call site that has not already minted a stopped generation.
    @discardableResult
    func beginFinalCaptureDrain(stoppedToken: Int?, captureToken: Int? = nil) -> Int {
        if var owed = owedFinalDrain {
            if owed.stoppedToken == nil {
                // The same stop reaching its generation: resolve it onto the
                // operation already owed, keeping the epoch recorded when it began.
                owed.stoppedToken = stoppedToken
                owedFinalDrain = owed
                return owed.operationID
            }
            finishOwedFinalDrain(owed.operationID, drained: false)
        }
        finalDrainOperationID &+= 1
        owedFinalDrain = OwedFinalDrain(
            operationID: finalDrainOperationID,
            captureToken: captureToken ?? startGeneration,
            stoppedToken: stoppedToken,
            originProjectID: activeRuntime.projectID
        )
        return finalDrainOperationID
    }

    /// Register a waiter for the exact final-drain completion the current stop owes.
    /// Returns `false` when the bounded wait elapsed first, so the caller can stay
    /// on the outgoing Project and offer a retry instead of guessing it drained.
    ///
    /// The elapsed bound fails only *this* waiter. The operation stays owed, because
    /// a tail that has not arrived is still owed and may still arrive; only an
    /// explicit recovery boundary retires it.
    func waitForFinalCaptureDrain(timeout: Duration, operationID expectedOperationID: Int? = nil) async -> Bool {
        guard let operationID = expectedOperationID ?? owedFinalDrain?.operationID else {
            return true
        }
        if let completion = lastFinalDrainCompletion, completion.operationID == operationID {
            return completion.drained
        }
        guard owedFinalDrain?.operationID == operationID else {
            return false
        }
        let waiterID = UUID()
        let timeoutTask = Task { @MainActor [weak self] in
            try? await Task.sleep(for: timeout)
            guard !Task.isCancelled else {
                return
            }
            self?.resumeFinalDrainWaiter(waiterID, drained: false)
        }
        defer { timeoutTask.cancel() }
        return await withCheckedContinuation { continuation in
            finalDrainWaiters[waiterID] = FinalDrainWaiter(
                operationID: operationID,
                continuation: continuation
            )
        }
    }

    /// Signal that the stopped capture identified by `stoppedToken` has folded and
    /// published its exact last snapshot and enqueued its terminal History write.
    ///
    /// Called from the exact ingest-chain completion, never from a timer. A
    /// completion stamped with any other stop is stale and releases nothing: a
    /// transition parked on the current boundary must not be resumed by a
    /// superseded capture's callback.
    func completeFinalCaptureDrain(stoppedToken: Int, succeeded: Bool = true) {
        guard let owed = owedFinalDrain, owed.stoppedToken == stoppedToken else {
            return
        }
        finishOwedFinalDrain(owed.operationID, drained: succeeded)
    }

    /// The current capture is definitively over and owes no further batch even
    /// though it never reached a stopped-generation boundary — a helper failure, or
    /// a stop abandoned before its generation was minted. Nothing more will be
    /// folded, but this is not a confirmed drain. Keep the current Project and
    /// require an explicit retry after the failure has been surfaced.
    func abortOwedFinalCaptureDrain() {
        guard let owed = owedFinalDrain else {
            return
        }
        finishOwedFinalDrain(owed.operationID, drained: false)
    }

    // MARK: Private

    private func resumeFinalDrainWaiter(_ id: UUID, drained: Bool) {
        guard let waiter = finalDrainWaiters.removeValue(forKey: id) else {
            return
        }
        waiter.continuation.resume(returning: drained)
    }

    /// Retire one owed drain and release exactly the waiters parked on it.
    private func finishOwedFinalDrain(_ operationID: Int, drained: Bool) {
        lastFinalDrainCompletion = (operationID, drained)
        if owedFinalDrain?.operationID == operationID {
            owedFinalDrain = nil
        }
        for (id, waiter) in finalDrainWaiters where waiter.operationID == operationID {
            finalDrainWaiters.removeValue(forKey: id)
            waiter.continuation.resume(returning: drained)
        }
    }
}
