//
//  SOCKSServer.swift
//  S5
//
//  Created by Luo Sheng on 15/10/1.
//  Copyright © 2015年 Pop Tap. All rights reserved.
//

import Foundation
import CocoaAsyncSocket

struct SOCKSServer {
    
    private let socket: GCDAsyncSocket
    
    init(port: UInt16) throws {
        socket = GCDAsyncSocket(delegate: nil, delegateQueue: dispatch_get_global_queue(0, 0))
        socket.delegate = self as? AnyObject
        try socket.acceptOnPort(port)
    }
    
}
