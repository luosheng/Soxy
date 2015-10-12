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

struct SoxProxy {
    static let SOCKSVersion: UInt8 = 0x5
    static let SOCKSReserved: UInt8 = 0x0
}

func toByteArray<T>(var value: T) -> [UInt8] {
    return withUnsafePointer(&value) {
        Array(UnsafeBufferPointer(start: UnsafePointer<UInt8>($0), count: sizeof(T)))
    }
}

protocol NSDataConvertible {
    init(data: NSData) throws
    var data: NSData? { get }
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

extension GCDAsyncSocket {
    func writeData<T where T: NSDataConvertible, T: Taggable>(t: T) {
        if let data = t.data {
            self.writeData(data, withTimeout: -1, tag: t.tag)
        }
    }
    
    func readData<T where T: Taggable>(t: T) {
        self.readDataWithTimeout(-1, tag: t.tag)
    }
}
