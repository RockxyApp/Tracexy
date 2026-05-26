//
//  Item.swift
//  Tracexy
//
//  Created by Stephen on 26/5/26.
//

import Foundation
import SwiftData

@Model
final class Item {
    var timestamp: Date
    
    init(timestamp: Date) {
        self.timestamp = timestamp
    }
}
