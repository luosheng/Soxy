//
//  SOCKSServer.swift
//  S5
//
//  Created by Luo Sheng on 15/10/1.
//  Copyright © 2015年 Pop Tap. All rights reserved.
//

import Foundation
import CocoaAsyncSocket

class SOCKSServer: GCDAsyncSocketDelegate {
    
    private let socket: GCDAsyncSocket
    private var connections: [SOCKSConnection]
    
    init(port: UInt16) throws {
        connections = []
        socket = GCDAsyncSocket(delegate: nil, delegateQueue: dispatch_get_global_queue(0, 0))
        socket.delegate = self
        try socket.acceptOnPort(port)
    }
    
    deinit {
        self.disconnectAll()
    }
    
    func disconnectAll() {
        for connection in connections {
            connection.disconnect()
        }
    }
    
    // MARK: - GCDAsyncSocketDelegate
    
    @objc func socket(sock: GCDAsyncSocket!, didAcceptNewSocket newSocket: GCDAsyncSocket!) {
        let connection = SOCKSConnection(socket: newSocket)
        connections.append(connection)
    }
}

// MARK: -

class SOCKSConnection: GCDAsyncSocketDelegate {
    
    enum SocketTag: Int {
        case
/* 
+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+ 
*/
        HandshakeVersion = 5,
        HandshakeNumberOfAuthenticationMethods,
        HandshakeAuthenticationMethod
        
        func dataLength() -> UInt {
            switch self {
                case .HandshakeVersion,
                .HandshakeNumberOfAuthenticationMethods:
                return 1
            default:
                return 0
            }
        }
    }
    
    private let clientSocket: GCDAsyncSocket
    
    init(socket: GCDAsyncSocket) {
        clientSocket = socket
        let queue = dispatch_queue_create("net.luosheng.SOCKSConnection.DelegateQueue", DISPATCH_QUEUE_SERIAL)
        clientSocket.setDelegate(self, delegateQueue: queue)
        self.beginHandshake()
    }
    
    func disconnect() {
        clientSocket.disconnect()
    }
    
    // MARK: - Private methods
    
    private func beginHandshake() {
        clientSocket.readData(.HandshakeVersion)
    }
    
    // MARK: - GCDAsyncSocketDelegate

    @objc func socket(sock: GCDAsyncSocket!, didReadData data: NSData!, withTag tag: Int) {
        switch tag {
        case SocketTag.HandshakeVersion.rawValue:
            break
        default:
            break
        }
    }
}

// MARK: -

extension GCDAsyncSocket {
    func readData(tag: SOCKSConnection.SocketTag) {
        return self.readDataToLength(tag.dataLength(), withTimeout: -1, tag: tag.rawValue)
    }
}
