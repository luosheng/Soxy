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
    
    enum SocketTag: UInt8 {
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
        HandshakeAuthenticationMethod,
        
/*
 +----+-----+-------+------+----------+----------+
 |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 +----+-----+-------+------+----------+----------+
 | 1  |  1  | X'00' |  1   | Variable |    2     |
 +----+-----+-------+------+----------+----------+

 o  VER    protocol version: X'05'
 o  CMD
    o  CONNECT X'01'
    o  BIND X'02'
    o  UDP ASSOCIATE X'03'
 o  RSV    RESERVED
 o  ATYP   address type of following address
    o  IP V4 address: X'01'
    o  DOMAINNAME: X'03'
    o  IP V6 address: X'04'
 o  DST.ADDR       desired destination address
 o  DST.PORT desired destination port in network octet order
*/
        RequestHeaderFragment,
        RequestAddressType,
        RequestIPv4Address,
        RequestIPv6Address,
        RequestDomainNameLength,
        RequestDomainName,
        RequestPort
        
        func dataLength() -> Int {
            switch self {
                case .HandshakeVersion,
                .HandshakeNumberOfAuthenticationMethods,
                .RequestAddressType,
                .RequestDomainNameLength:
                return 1
            case .RequestHeaderFragment:
                return 3
            case .RequestIPv4Address:
                return 4
            case .RequestIPv6Address:
                return 16
            case .RequestPort:
                return 2
            default:
                return 0
            }
        }
    }
    
/*
 o  X'00' NO AUTHENTICATION REQUIRED
 o  X'01' GSSAPI
 o  X'02' USERNAME/PASSWORD
 o  X'03' to X'7F' IANA ASSIGNED
 o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
 o  X'FF' NO ACCEPTABLE METHODS
*/
    enum AuthenticationMethod: UInt8 {
        case
        None = 0x00,
        GSSAPI,
        UsernamePassword
    }
    
    enum RequestCommand: UInt8 {
        case
        Connect = 0x01,
        Bind,
        UDPAssociate
    }
    
    enum AddressType: UInt8 {
        case IPv4 = 0x01
        case IPv6 = 0x04
        case DomainName = 0x03
    }
    
    enum SocketError: ErrorType {
        case InvalidSOCKSVersion
        case UnableToRetrieveNumberOfAuthenticationMethods
        case SupportedAuthenticationMethodNotFound
        case WrongNumberOfAuthenticationMethods
        case InvalidRequestCommand
        case InvalidHeaderFragment
        case InvalidAddressType
        case InvalidDomainLength
        case InvalidDomainName
        case InvalidPort
    }
    
    private let clientSocket: GCDAsyncSocket
    private var numberOfAuthenticationMethods = 0
    private var requestCommand: RequestCommand = .Connect
    private var domainLength = 0
    
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
    
    private func readSOCKSVersion(data: NSData) throws {
        guard data.length == SocketTag.HandshakeVersion.dataLength() else {
            throw SocketError.InvalidSOCKSVersion
        }
        var version: UInt8 = 0
        data.getBytes(&version, length: data.length)
        
        guard version == SocketTag.HandshakeVersion.rawValue else {
            throw SocketError.InvalidSOCKSVersion
        }
        clientSocket.readData(.HandshakeNumberOfAuthenticationMethods)
    }
    
    private func readNumberOfAuthenticationMethods(data: NSData) throws {
        guard (data.length == SocketTag.HandshakeNumberOfAuthenticationMethods.dataLength()) else {
            throw SocketError.UnableToRetrieveNumberOfAuthenticationMethods
        }
        data.getBytes(&numberOfAuthenticationMethods, length: data.length)
        clientSocket.readDataToLength(UInt(numberOfAuthenticationMethods), withTimeout: -1, tag: Int(SocketTag.HandshakeAuthenticationMethod.rawValue))
    }
    
    private func readAuthenticationMethods(data: NSData) throws {
        guard data.length == numberOfAuthenticationMethods else {
            throw SocketError.WrongNumberOfAuthenticationMethods
        }
        var authMethods: [UInt8] = Array<UInt8>(count: numberOfAuthenticationMethods, repeatedValue: 0)
        data.getBytes(&authMethods, length: numberOfAuthenticationMethods)
        
        guard authMethods.contains(AuthenticationMethod.None.rawValue) else {
            throw SocketError.SupportedAuthenticationMethodNotFound
        }
        /*
         +----+--------+
         |VER | METHOD |
         +----+--------+
         | 1  |   1    |
         +----+--------+
        */
        let methodSelectionBytes: [UInt8] = [SocketTag.HandshakeVersion.rawValue, AuthenticationMethod.None.rawValue];
        let methodSelectionData = NSData(bytes: methodSelectionBytes, length: methodSelectionBytes.count)
        clientSocket.writeData(methodSelectionData, withTimeout: -1, tag: 0)
        clientSocket.readData(.RequestHeaderFragment)
    }
    
    private func readHeaderFragment(data: NSData) throws {
        guard data.length == SocketTag.RequestHeaderFragment.dataLength() else {
            throw SocketError.InvalidHeaderFragment
        }
        
        var header: [UInt8] = Array<UInt8>(count: data.length, repeatedValue: 0)
        data.getBytes(&header, length: data.length)
        
        let version = header[0]
        if (version != SocketTag.HandshakeVersion.rawValue) {
            throw SocketError.InvalidSOCKSVersion
        }
        
        guard let cmd = RequestCommand(rawValue: header[1]) else {
            throw SocketError.InvalidRequestCommand
        }
        requestCommand = cmd
        
        // Reserved
        _ = header[2]
        
        clientSocket.readData(.RequestAddressType)
    }
    
    private func readAddressType(data: NSData) throws {
        guard data.length == SocketTag.RequestAddressType.dataLength() else {
            throw SocketError.InvalidAddressType
        }
        
        var addressTypeByte: UInt8 = 0
        data.getBytes(&addressTypeByte, length: data.length)
        
        guard let addressType = AddressType(rawValue: addressTypeByte) else {
            throw SocketError.InvalidAddressType
        }
        
        switch addressType {
        case .IPv4:
            clientSocket.readData(.RequestIPv4Address)
            break
        case .IPv6:
            clientSocket.readData(.RequestIPv6Address)
            break
        case .DomainName:
            clientSocket.readData(.RequestDomainNameLength)
            break
        }
    }
    
    private func readDomainLength(data: NSData) throws {
        guard data.length == SocketTag.RequestDomainNameLength.dataLength() else {
            throw SocketError.InvalidDomainLength
        }
        
        data.getBytes(&domainLength, length: data.length)
        clientSocket.readDataToLength(UInt(domainLength), withTimeout: -1, tag: Int(SocketTag.RequestDomainName.rawValue))
    }
    
    private func readDomainName(data: NSData) throws {
        guard data.length == domainLength else {
            throw SocketError.InvalidDomainName
        }
        
        let domainName = String(data: data, encoding: NSASCIIStringEncoding)
        print(domainName)
        clientSocket.readData(.RequestPort)
    }
    
    private func readPort(data: NSData) throws {
        guard data.length == SocketTag.RequestPort.dataLength() else {
            throw SocketError.InvalidPort
        }
        
        var port: [UInt8] = [UInt8](count: data.length, repeatedValue: 0)
        data.getBytes(&port, length: data.length)
        let targetPort = Int(port[0]) << 8 | Int(port[1])
        print("target port: \(targetPort)")
    }
    
    // MARK: - GCDAsyncSocketDelegate

    @objc func socket(sock: GCDAsyncSocket!, didReadData data: NSData!, withTag tag: Int) {
        print("data: \(data)")
        guard let socketTag = SocketTag(rawValue: UInt8(tag)) else {
            return
        }
        do {
            switch socketTag {
            case .HandshakeVersion:
                try self.readSOCKSVersion(data)
                break
            case .HandshakeNumberOfAuthenticationMethods:
                try self.readNumberOfAuthenticationMethods(data)
                break
            case .HandshakeAuthenticationMethod:
                try self.readAuthenticationMethods(data)
                break
            case .RequestHeaderFragment:
                try self.readHeaderFragment(data)
                break
            case .RequestAddressType:
                try self.readAddressType(data)
                break
            case .RequestDomainNameLength:
                try self.readDomainLength(data)
                break
            case .RequestDomainName:
                try self.readDomainName(data)
                break
            case .RequestPort:
                try self.readPort(data)
                break
            default:
                break
            }
        } catch {
            print(error)
            clientSocket.disconnect()
        }
    }
}

// MARK: -

extension GCDAsyncSocket {
    func readData(tag: SOCKSConnection.SocketTag) {
        return self.readDataToLength(UInt(tag.dataLength()), withTimeout: -1, tag: Int(tag.rawValue))
    }
}
