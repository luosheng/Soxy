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

extension GCDAsyncSocket {
    func writeData(data: NSDataConvertible, timeout:NSTimeInterval, tag: Int) {
        if let data = data.data {
            self.writeData(data, withTimeout: timeout, tag: tag)
        }
    }
}