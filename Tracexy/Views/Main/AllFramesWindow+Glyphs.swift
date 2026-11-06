import SwiftUI

// MARK: - Frame row glyphs

extension AllFramesWindow {
    @ViewBuilder
    func frameHighlightGlyph(_ row: CaptureFrameRow) -> some View {
        if coordinator.allFrames.highlightedFrameOrdinals.contains(row.id) {
            Image(systemName: "circle.fill")
                .font(.system(size: Theme.Icon.small))
                .foregroundStyle(.orange)
                .help("Highlighted by Frame Expression: \(coordinator.allFrames.highlightedFrameExpressionText)")
                .accessibilityLabel("Highlighted by Frame Expression")
                .accessibilityHint(coordinator.allFrames.highlightedFrameExpressionText)
        }
    }

    @ViewBuilder
    func temporaryConversationColorGlyph(_ row: CaptureFrameRow) -> some View {
        if let sessionID = row.sessionID,
           let slot = coordinator.allFrames.temporaryConversationColorSlots[sessionID],
           TemporaryConversationColorPalette.backgroundRGB.indices.contains(slot)
        {
            Image(systemName: "circle.fill")
                .font(.system(size: Theme.Icon.small))
                .foregroundStyle(
                    selection == row.id || coordinator.allFrames.ignored.contains(row.id)
                        ? Color.secondary : frameRuleColor(TemporaryConversationColorPalette.foregroundRGB)
                )
                .help("Temporary conversation color \(slot + 1)")
                .accessibilityLabel("Temporary conversation color \(slot + 1)")
        }
    }

    @ViewBuilder
    func frameColorRuleGlyph(_ row: CaptureFrameRow) -> some View {
        if row.sessionID.flatMap({ coordinator.allFrames.temporaryConversationColorSlots[$0] }) != nil {
            EmptyView()
        } else if let id = coordinator.allFrames.frameColorRuleByOrdinal[row.id],
                  let rule = coordinator.allFrames.frameColorRuleLibrary.rules.first(where: { $0.id == id })
        {
            Image(systemName: "circle.fill")
                .font(.system(size: Theme.Icon.small))
                .foregroundStyle(frameRuleColor(rule.backgroundRGB))
                .help("Colorized by \(rule.name): \(rule.expression)")
                .accessibilityLabel("Colorized by \(rule.name)")
                .accessibilityHint(rule.expression)
        } else if coordinator.allFrames.frameColorRuleUnknownOrdinals.contains(row.id) {
            Image(systemName: "circle.dashed")
                .font(.system(size: Theme.Icon.small))
                .foregroundStyle(.secondary)
                .help("Color rule result unknown; no rule was applied")
                .accessibilityLabel("Color rule result unknown")
        }
    }

    @ViewBuilder
    func colorizedCell(_ row: CaptureFrameRow, @ViewBuilder content: () -> some View) -> some View {
        if let sessionID = row.sessionID,
           let slot = coordinator.allFrames.temporaryConversationColorSlots[sessionID],
           TemporaryConversationColorPalette.backgroundRGB.indices.contains(slot),
           selection != row.id, !coordinator.allFrames.ignored.contains(row.id)
        {
            content()
                .frame(maxWidth: .infinity, alignment: .leading)
                .foregroundStyle(frameRuleColor(TemporaryConversationColorPalette.foregroundRGB))
                .background(frameRuleColor(TemporaryConversationColorPalette.backgroundRGB[slot]))
                .help("Temporary conversation color \(slot + 1)")
                .accessibilityHint("Temporary conversation color \(slot + 1); overrides saved coloring rules")
        } else if let id = coordinator.allFrames.frameColorRuleByOrdinal[row.id],
                  let rule = coordinator.allFrames.frameColorRuleLibrary.rules.first(where: { $0.id == id }),
                  selection != row.id, !coordinator.allFrames.ignored.contains(row.id)
        {
            content()
                .frame(maxWidth: .infinity, alignment: .leading)
                .foregroundStyle(frameRuleColor(rule.foregroundRGB))
                .background(frameRuleColor(rule.backgroundRGB))
                .help("Colorized by \(rule.name): \(rule.expression)")
                .accessibilityHint("Colorized by rule \(rule.name): \(rule.expression)")
        } else if coordinator.allFrames.ignored.contains(row.id), selection != row.id {
            content().foregroundStyle(.tertiary)
        } else {
            content()
        }
    }
}
