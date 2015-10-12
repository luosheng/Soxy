//
//  SOCKSServer.swift
//  S5
//
//  Created by Luo Sheng on 15/10/1.
//  Copyright © 2015年 Pop Tap. All rights reserved.
//

import Foundation
import CocoaAsyncSocket
import NetworkExtension

// MARK: -

protocol ConnectionDelegate {
    func connectionDidClose(connection: Connection)
}

// MARK: -

public class Connection: GCDAsyncSocketDelegate, Hashable {
    
    static let replyTag = 100
    
    enum Phase: Int, Taggable {
        case MethodSelection = 10
        case MethodSelectionReply
        case Request
        case RequestReply
        
        var tag: Int {
            get {
                return self.rawValue
            }
        }
    }
    
/*
 +----+----------+----------+
 |VER | NMETHODS | METHODS  |
 +----+----------+----------+
 | 1  |    1     | 1 to 255 |
 +----+----------+----------+
*/
    struct MethodSelection: NSDataConvertible, Taggable {
        let numberOfAuthenticationMethods: UInt8
        let authenticationMethods: [AuthenticationMethod]
        
        init(data: NSData) throws {
            var bytes: [UInt8] = [UInt8](count: data.length, repeatedValue: 0)
            data.getBytes(&bytes, length: bytes.count)
            
            guard bytes.count >= 3 else {
                throw SocketError.WrongNumberOfAuthenticationMethods
            }
            
            guard bytes[0] == SoxProxy.SOCKSVersion else {
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
        
        var data: NSData? {
            get {
                var bytes = [UInt8]()
                
                bytes.append(SoxProxy.SOCKSVersion)
                bytes.append(numberOfAuthenticationMethods)
                bytes.appendContentsOf(authenticationMethods.map() { $0.rawValue })
                
                let data = NSData(bytes: bytes, length: bytes.count)
                return data
            }
        }
    }
    
/*
 +----+--------+
 |VER | METHOD |
 +----+--------+
 | 1  |   1    |
 +----+--------+
*/
    struct MethodSelectionReply: NSDataConvertible, Taggable {
        let method: AuthenticationMethod
        
        init(data: NSData) throws {
            throw SocketError.NotImplemented
        }
        
        init(method: AuthenticationMethod) {
            self.method = method
        }
        
        var data: NSData? {
            get {
                var bytes = [SoxProxy.SOCKSVersion, method.rawValue]
                return NSData(bytes: &bytes, length: bytes.count)
            }
        }
    }

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
    struct Request: NSDataConvertible, Taggable {
        enum Command: UInt8 {
            case Connect = 0x01
            case Bind
            case UDPAssociate
        }
        
        let command: Command
        let addressType: AddressType
        let targetHost: String
        let targetPort: UInt16
        
        init(data: NSData) throws {
            var bytes = [UInt8](count: data.length, repeatedValue: 0)
            data.getBytes(&bytes, length: bytes.count)
            
            var offset = 0
            
            guard bytes[offset++] == SoxProxy.SOCKSVersion else {
                throw SocketError.InvalidSOCKSVersion
            }
            
            guard let cmd = Command(rawValue: bytes[offset++]) else {
                throw SocketError.InvalidRequestCommand
            }
            command = cmd
            
            // Reserved
            _ = bytes[offset++]
            
            guard let atyp = AddressType(rawValue: bytes[offset++]) else {
                throw SocketError.InvalidAddressType
            }
            addressType = atyp
            
            switch addressType {
            case .DomainName:
                let domainNameLength = bytes[offset++]
                guard let domainName = String(bytes: bytes[offset..<(offset + Int(domainNameLength))], encoding: NSASCIIStringEncoding) else {
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
        
        var data: NSData? {
            get {
                var bytes: [UInt8] = [SoxProxy.SOCKSVersion, command.rawValue, SoxProxy.SOCKSReserved, addressType.rawValue]
                
                switch addressType {
                case .DomainName:
                    bytes.append(UInt8(targetHost.characters.count))
                    bytes.appendContentsOf([UInt8](targetHost.utf8))
                    break
                default:
                    break
                }
                
                let bindPort = targetPort.littleEndian.byteSwapped
                bytes.appendContentsOf(toByteArray(bindPort))
                
                return NSData(bytes: bytes, length: bytes.count)
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
        case NotImplemented
    }
    
/*
 +----+-----+-------+------+----------+----------+
 |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
 +----+-----+-------+------+----------+----------+
 | 1  |  1  | X'00' |  1   | Variable |    2     |
 +----+-----+-------+------+----------+----------+
*/
    struct Reply: NSDataConvertible, Taggable {
        enum Field: UInt8 {
            case Succeed = 0x00
            case GeneralSOCKSServerFailure
            case ConnectionNotAllowedByRuleset
            case NetworkUnreachable
            case ConnectionRefused
            case TTLExpired
            case CommandNotSupported
            case AddressTypeNotSupported
        }
        let field: Field
        let addressType: AddressType
        let address: String
        let port: UInt16
        
        init(data: NSData) throws {
            throw SocketError.NotImplemented
        }
        
        init(field: Field, addressType: AddressType, address: String, port: UInt16) {
            self.field = field
            self.addressType = addressType
            self.address = address
            self.port = port
        }
        
        var data: NSData? {
            get {
                var bytes: [UInt8] = [SoxProxy.SOCKSVersion, field.rawValue, SoxProxy.SOCKSReserved]
                
                // If reply field is anything other than Succeed, just reply with
                // VER, REP, RSV
                guard field == .Succeed else {
                    return NSData(bytes: &bytes, length: bytes.count)
                }
                
                bytes.append(addressType.rawValue)
                
                switch addressType {
                case .DomainName:
                    bytes.append(UInt8(address.characters.count))
                    bytes.appendContentsOf([UInt8](address.utf8))
                    break
                default:
                    break
                }
                
                let data = NSMutableData(bytes: bytes, length: bytes.count)
                var networkOctetOrderPort: UInt16 = port.littleEndian
                data.appendBytes(&networkOctetOrderPort, length: 2)
                return data
            }
        }
        
        var tag: Int {
            get {
                switch field {
                case .Succeed:
                    return Connection.replyTag
                default:
                    return 0
                }
            }
        }
    }
    
    var delgate: ConnectionDelegate?
    weak var server: Server?
    private let delegateQueue: dispatch_queue_t
    private let clientSocket: GCDAsyncSocket
    private var directSocket: GCDAsyncSocket?
    private var methodSelection: MethodSelection?
    private var request: Request?
    private var proxySocket: GCDAsyncSocket?
    
    public var hashValue: Int {
        get {
            return ObjectIdentifier(self).hashValue
        }
    }
    
    init(socket: GCDAsyncSocket) {
        clientSocket = socket
        delegateQueue = dispatch_queue_create("net.luosheng.SOCKSConnection.DelegateQueue", DISPATCH_QUEUE_SERIAL)
        clientSocket.setDelegate(self, delegateQueue: delegateQueue)
        clientSocket.readData(Phase.MethodSelection)
    }
    
    func disconnect() {
        clientSocket.disconnectAfterReadingAndWriting()
        directSocket?.disconnectAfterReadingAndWriting()
        proxySocket?.disconnectAfterReadingAndWriting()
    }
    
    // MARK: - Private methods
    
    private func processMethodSelection(data: NSData) throws {
        let methodSelection = try MethodSelection(data: data)
        guard methodSelection.authenticationMethods.contains(.None) else {
            throw SocketError.SupportedAuthenticationMethodNotFound
        }
        self.methodSelection = methodSelection
        let reply = MethodSelectionReply(method: .None)
        clientSocket.writeData(reply)
        clientSocket.readData(Phase.Request)
    }
    
    private func processRequest(data: NSData) throws {
        let request = try Request(data: data)
        let reply = Reply(field: .Succeed, addressType: request.addressType, address: request.targetHost, port: request.targetPort)
        self.request = request
        clientSocket.writeData(reply)
        clientSocket.readDataWithTimeout(-1, tag: 0)
    }
    
    // MARK: - GCDAsyncSocketDelegate
    
    @objc public func socketDidDisconnect(sock: GCDAsyncSocket!, withError err: NSError!) {
        self.disconnect()
        delgate?.connectionDidClose(self)
    }

    @objc public func socket(sock: GCDAsyncSocket!, didReadData data: NSData!, withTag tag: Int) {
        do {
            guard let phase = Phase(rawValue: tag) else {
                // If the tag is not specified, it's in proxy mode
                if sock == clientSocket {
                    if server?.proxyServer != nil {
                        proxySocket?.writeData(data, withTimeout: -1, tag: 0)
                    } else {
                        directSocket?.writeData(data, withTimeout: -1, tag: 0)
                    }
                } else {
                    clientSocket.writeData(data, withTimeout: -1, tag: 0)
                }
                sock.readDataWithTimeout(-1, tag: 0)
                return
            }
            switch phase {
            case .MethodSelection:
                try self.processMethodSelection(data)
                break
            case .Request:
                try self.processRequest(data)
                break
            case .MethodSelectionReply:
                if let request = request {
                    proxySocket?.writeData(request)
                    proxySocket?.readData(Phase.RequestReply)
                }
                break
            case .RequestReply:
                clientSocket.readDataWithTimeout(-1, tag: 0)
                proxySocket?.readDataWithTimeout(-1, tag: 0)
                break
            }
        } catch {
            print("error: \(error)")
            self.disconnect()
        }
    }
    
    @objc public func socket(sock: GCDAsyncSocket!, didWriteDataWithTag tag: Int) {
        if tag == Connection.replyTag {
            
            if let proxyServer = server?.proxyServer {
                proxySocket = GCDAsyncSocket(delegate: self, delegateQueue: delegateQueue)
                try! proxySocket?.connectToHost(proxyServer.address, onPort: UInt16(proxyServer.port))
                if let methodSelection = methodSelection {
                    proxySocket?.writeData(methodSelection)
                    proxySocket?.readData(Phase.MethodSelectionReply)
                }
            } else {
                directSocket = GCDAsyncSocket(delegate: self, delegateQueue: delegateQueue)
                guard let request = request else {
                    return
                }
                do {
                    try directSocket?.connectToHost(request.targetHost, onPort: request.targetPort, withTimeout: -1)
                    clientSocket.readDataWithTimeout(-1, tag: 0)
                    directSocket?.readDataWithTimeout(-1, tag: 0)
                } catch {
                    clientSocket.disconnectAfterReadingAndWriting()
                }
            }
        }
    }
}

public func ==(lhs: Connection, rhs: Connection) -> Bool {
    return ObjectIdentifier(lhs) == ObjectIdentifier(rhs)
}
