//
//  SoxProxy.swift
//  SoxProxy
//
//  Created by Luo Sheng on 15/10/3.
//  Copyright © 2015年 Pop Tap. All rights reserved.
//

import Foundation
import CocoaAsyncSocket

protocol NSDataConvertible {
    init(data: NSData) throws
    var data: NSData? { get }
}

protocol Taggable {
    var tag: Int { get }
}

extension Taggable {
    var tag: Int {
        get {
            return 0
        }
    }
}

extension GCDAsyncSocket {
    func writeData<T where T: NSDataConvertible, T: Taggable>(t: T) {
        if let data = t.data {
            self.writeData(data, withTimeout: -1, tag: t.tag)
        }
    }
}