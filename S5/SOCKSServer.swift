//
//  SOCKSServer.swift
//  S5
//
//  Created by Luo Sheng on 15/10/1.
//  Copyright © 2015年 Pop Tap. All rights reserved.
//

import Foundation
import CocoaAsyncSocket

// MARK: -

protocol SOCKSConnectionDelegate {
    func connectionDidClose(connection: SOCKSConnection)
}

// MARK: -

class SOCKSServer: GCDAsyncSocketDelegate, SOCKSConnectionDelegate {
    
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
    
    // MARK SOCKSConnectionDelegate
    
    func connectionDidClose(connection: SOCKSConnection) {
        if let index = connections.indexOf(connection) {
            connections.removeAtIndex(index)
        }
    }
}

// MARK: -

class SOCKSConnection: GCDAsyncSocketDelegate, Equatable {
    
    static let version: UInt8 = 5
    static let replyTag = 100
    
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
    
    enum Phase: Int {
        case
        MethodSelection = 10,
        Request
    }
    
    struct MethodSelection {
        let version: UInt8
        let numberOfAuthenticationMethods: UInt8
        let authenticationMethods: [AuthenticationMethod]
        
        init(bytes: [UInt8]) throws {
            guard bytes.count >= 3 else {
                throw SocketError.WrongNumberOfAuthenticationMethods
            }
            
            version = bytes[0]
            
            guard version == SOCKSConnection.version else {
                throw SocketError.InvalidSOCKSVersion
            }
            
            numberOfAuthenticationMethods = bytes[1]
            
            guard bytes.count == 1 + 1 + Int(numberOfAuthenticationMethods) else {
                throw SocketError.WrongNumberOfAuthenticationMethods
            }
            
            authenticationMethods = try bytes[2...(bytes.count - 1)].map() {
                guard let method = AuthenticationMethod(rawValue: $0) else {
                    throw SocketError.NotSupportedAuthenticationMethod
                }
                return method
            }
        }
    }
    
    struct MethodSelectionReply {
        let method: AuthenticationMethod
        
        var data: NSData {
            get {
                var bytes:[UInt8] = [SOCKSConnection.version, method.rawValue]
                return NSData(bytes: &bytes, length: bytes.count)
            }
        }
    }
    
    struct Request {
        enum Command: UInt8 {
            case
            Connect = 0x01,
            Bind,
            UDPAssociate
        }
        
        let version: UInt8
        let command: Command
        let reserved: UInt8
        let addressType: AddressType
        let targetHost: String
        let targetPort: UInt16
        
        init(data: NSData) throws {
            var bytes = [UInt8](count: data.length, repeatedValue: 0)
            data.getBytes(&bytes, length: bytes.count)
            
            var offset = 0
            
            version = bytes[offset++]
            guard version == SOCKSConnection.version else {
                throw SocketError.InvalidSOCKSVersion
            }
            
            guard let cmd = Command(rawValue: bytes[offset++]) else {
                throw SocketError.InvalidRequestCommand
            }
            command = cmd
            
            reserved = bytes[offset++]
            
            guard let atyp = AddressType(rawValue: bytes[offset++]) else {
                throw SocketError.InvalidAddressType
            }
            addressType = atyp
            
            switch addressType {
            case .DomainName:
                let domainNameLength = bytes[offset++]
                guard let domainName = String(bytes: bytes[offset...(offset + Int(domainNameLength))], encoding: NSASCIIStringEncoding) else {
                    throw SocketError.InvalidDomainName
                }
                targetHost = domainName
                offset += Int(domainNameLength)
                break
            default:
                targetHost = ""
                break
            }
            
            var bindPort: UInt16 = 0
            data.getBytes(&bindPort, range: NSRange(location: offset, length: 2))
            targetPort = bindPort.bigEndian
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
        case NotSupportedAuthenticationMethod
        case SupportedAuthenticationMethodNotFound
        case WrongNumberOfAuthenticationMethods
        case InvalidRequestCommand
        case InvalidHeaderFragment
        case InvalidAddressType
        case InvalidDomainLength
        case InvalidDomainName
        case InvalidPort
    }
    
    
/*
 +----+-----+-------+------+----------+----------+
 |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
 +----+-----+-------+------+----------+----------+
 | 1  |  1  | X'00' |  1   | Variable |    2     |
 +----+-----+-------+------+----------+----------+
*/
    struct Reply {
        enum Field: UInt8 {
            case
            Succeed = 0x00,
            GeneralSOCKSServerFailure,
            ConnectionNotAllowedByRuleset,
            NetworkUnreachable,
            ConnectionRefused,
            TTLExpired,
            CommandNotSupported,
            AddressTypeNotSupported
        }
        static var version: UInt8 = 0x05
        var field: Field
        static var reserved: UInt8 = 0x00
        var addressType: AddressType
        var address: String
        var port: UInt16
        
        var data: NSData {
            get {
                let data = NSMutableData()
                data.appendBytes(&Reply.version, length: 1)
                
                var fieldValue = field.rawValue
                data.appendBytes(&fieldValue, length: 1)
                
                data.appendBytes(&Reply.reserved, length: 1)
                
                // If reply field is anything other than Succeed, just reply with
                // VER, REP, RSV
                guard field == .Succeed else {
                    return data
                }
                
                var addressTypeValue = addressType.rawValue
                data.appendBytes(&addressTypeValue, length: 1)
                
                switch addressType {
                case .DomainName:
                    var domainLength: UInt8 = UInt8(address.characters.count)
                    data.appendBytes(&domainLength, length: 1)
                    
                    var domainName = [UInt8](address.utf8)
                    data.appendBytes(&domainName, length: address.characters.count)
                    break
                default:
                    break
                }
                
                var networkOctetOrderPort = port.littleEndian
                data.appendBytes(&networkOctetOrderPort, length: 2)
                
                return data
            }
        }
    }
    
    var delgate: SOCKSConnectionDelegate?
    private let clientSocket: GCDAsyncSocket
    private var numberOfAuthenticationMethods = 0
    private var requestCommand: RequestCommand = .Connect
    private var domainLength = 0
    private var targetHost: String?
    private var targetPort: UInt16?
    private var targetSocket: GCDAsyncSocket?
    private let delegateQueue: dispatch_queue_t
    private var request: Request?
    
    init(socket: GCDAsyncSocket) {
        clientSocket = socket
        delegateQueue = dispatch_queue_create("net.luosheng.SOCKSConnection.DelegateQueue", DISPATCH_QUEUE_SERIAL)
        clientSocket.setDelegate(self, delegateQueue: delegateQueue)
        self.beginHandshake()
    }
    
    func disconnect() {
        clientSocket.disconnect()
        targetSocket?.disconnect()
    }
    
    // MARK: - Private methods
    
    private func beginHandshake() {
        clientSocket.readDataWithTimeout(-1, tag: Phase.MethodSelection.rawValue)
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
        
        guard let domainName = String(data: data, encoding: NSASCIIStringEncoding) else {
            throw SocketError.InvalidDomainName
        }
        targetHost = domainName
        clientSocket.readData(.RequestPort)
    }
    
    private func readPort(data: NSData) throws {
        guard data.length == SocketTag.RequestPort.dataLength() else {
            throw SocketError.InvalidPort
        }
        
        var port: UInt16 = 0
        data.getBytes(&port, length: data.length)
        targetPort = port.bigEndian
    }
    
    private func processMethodSelection(data: NSData) throws {
        var bytes: [UInt8] = [UInt8](count: data.length, repeatedValue: 0)
        data.getBytes(&bytes, length: bytes.count)
        
        let methodSelection = try MethodSelection(bytes: bytes)
        guard methodSelection.authenticationMethods.contains(.None) else {
            throw SocketError.SupportedAuthenticationMethodNotFound
        }
        
        let reply = MethodSelectionReply(method: .None)
        clientSocket.writeData(reply.data, withTimeout: -1, tag: 0)
        clientSocket.readDataWithTimeout(-1, tag: Phase.Request.rawValue)
    }
    
    private func processRequest(data: NSData) throws {
        let request = try Request(data: data)
        let reply = Reply(field: .Succeed, addressType: request.addressType, address: request.targetHost, port: request.targetPort)
        self.request = request
        clientSocket.writeData(reply.data, withTimeout: -1, tag: SOCKSConnection.replyTag)
        clientSocket.readDataWithTimeout(-1, tag: 0)
    }
    
    // MARK: - GCDAsyncSocketDelegate
    
    @objc func socketDidDisconnect(sock: GCDAsyncSocket!, withError err: NSError!) {
        clientSocket.disconnect()
        targetSocket?.disconnect()
        delgate?.connectionDidClose(self)
    }

    @objc func socket(sock: GCDAsyncSocket!, didReadData data: NSData!, withTag tag: Int) {
        print("data: \(data)")
        do {
            switch tag {
            case Phase.MethodSelection.rawValue:
                try self.processMethodSelection(data)
                break
            case Phase.Request.rawValue:
                try self.processRequest(data)
                break
            default:
                // If the tag is not specified, it's in proxy mode
                if sock == clientSocket {
                    targetSocket?.writeData(data, withTimeout: -1, tag: 0)
                } else {
                    clientSocket.writeData(data, withTimeout: -1, tag: 0)
                }
                sock.readDataWithTimeout(-1, tag: 0)
                break
            }
        } catch {
            print("error: \(error)")
            self.disconnect()
        }
    }
    
    @objc func socket(sock: GCDAsyncSocket!, didWriteDataWithTag tag: Int) {
        if tag == SOCKSConnection.replyTag {
            targetSocket = GCDAsyncSocket(delegate: self, delegateQueue: delegateQueue)
            guard let request = request else {
                return
            }
            do {
                try targetSocket?.connectToHost(request.targetHost, onPort: request.targetPort, withTimeout: -1)
                clientSocket.readDataWithTimeout(-1, tag: 0)
                targetSocket?.readDataWithTimeout(-1, tag: 0)
            } catch {
                clientSocket.disconnectAfterReadingAndWriting()
            }
        }
    }
}

func ==(lhs: SOCKSConnection, rhs: SOCKSConnection) -> Bool {
    return ObjectIdentifier(lhs) == ObjectIdentifier(rhs)
}

// MARK: -

extension GCDAsyncSocket {
    func readData(tag: SOCKSConnection.SocketTag) {
        return self.readDataToLength(UInt(tag.dataLength()), withTimeout: -1, tag: Int(tag.rawValue))
    }
}
