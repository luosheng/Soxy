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

protocol ConnectionDelegate {
    func connectionDidClose(connection: Connection)
}

// MARK: -

public class Connection: GCDAsyncSocketDelegate, Hashable {
    
    static let version: UInt8 = 5
    static let replyTag = 100
    
    enum Phase: Int {
        case
        MethodSelection = 10,
        Request
    }
    
/*
 +----+----------+----------+
 |VER | NMETHODS | METHODS  |
 +----+----------+----------+
 | 1  |    1     | 1 to 255 |
 +----+----------+----------+
*/
    struct MethodSelection: NSDataConvertible {
        let version: UInt8
        let numberOfAuthenticationMethods: UInt8
        let authenticationMethods: [AuthenticationMethod]
        
        init(data: NSData) throws {
            var bytes: [UInt8] = [UInt8](count: data.length, repeatedValue: 0)
            data.getBytes(&bytes, length: bytes.count)
            
            guard bytes.count >= 3 else {
                throw SocketError.WrongNumberOfAuthenticationMethods
            }
            
            version = bytes[0]
            
            guard version == Connection.version else {
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
                
                bytes.append(version)
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
    struct MethodSelectionReply {
        let method: AuthenticationMethod
        
        var data: NSData {
            get {
                var bytes:[UInt8] = [Connection.version, method.rawValue]
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
            guard version == Connection.version else {
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
    
    var delgate: ConnectionDelegate?
    private let delegateQueue: dispatch_queue_t
    private let clientSocket: GCDAsyncSocket
    private var targetSocket: GCDAsyncSocket?
    private var request: Request?
    
    public var hashValue: Int {
        get {
            return ObjectIdentifier(self).hashValue
        }
    }
    
    init(socket: GCDAsyncSocket) {
        clientSocket = socket
        delegateQueue = dispatch_queue_create("net.luosheng.SOCKSConnection.DelegateQueue", DISPATCH_QUEUE_SERIAL)
        clientSocket.setDelegate(self, delegateQueue: delegateQueue)
        clientSocket.readDataWithTimeout(-1, tag: Phase.MethodSelection.rawValue)
    }
    
    func disconnect() {
        clientSocket.disconnectAfterReadingAndWriting()
        targetSocket?.disconnectAfterReadingAndWriting()
    }
    
    // MARK: - Private methods
    
    private func processMethodSelection(data: NSData) throws {
        let methodSelection = try MethodSelection(data: data)
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
        clientSocket.writeData(reply.data, withTimeout: -1, tag: Connection.replyTag)
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
                    targetSocket?.writeData(data, withTimeout: -1, tag: 0)
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
            }
        } catch {
            print("error: \(error)")
            self.disconnect()
        }
    }
    
    @objc public func socket(sock: GCDAsyncSocket!, didWriteDataWithTag tag: Int) {
        if tag == Connection.replyTag {
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

public func ==(lhs: Connection, rhs: Connection) -> Bool {
    return ObjectIdentifier(lhs) == ObjectIdentifier(rhs)
}
