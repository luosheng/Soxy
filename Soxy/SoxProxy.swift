//
//  SoxProxy.swift
//  SoxProxy
//
//  Created by Luo Sheng on 15/10/3.
//  Copyright © 2015年 Pop Tap. All rights reserved.
//

import Foundation
import CocoaAsyncSocket
import NetworkExtension

struct Soxy {
    struct SOCKS {
        static let version: UInt8 = 5
        static let reserved: UInt8 = 0
    }
}

extension UInt16 {
    func toByteArray() -> [UInt8] {
        return [UInt8(self >> 8 & 0x00FF), UInt8(self & 0x00FF)]
    }
}

protocol NSDataConvertible {
    init(data: Data) throws
    var data: Data? { get }
}

protocol Taggable {
    var tag: Int { get }
}

protocol Proxyable {
    var proxyServer: NEProxyServer? { get }
}

extension Taggable {
    var tag: Int {
        get {
            return 0
        }
    }
}
