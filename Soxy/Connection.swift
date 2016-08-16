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
    func connectionDidClose(_ connection: Connection)
}

// MARK: -

open class Connection: GCDAsyncSocketDelegate, Hashable {
    
    static let replyTag = 100
    
    enum Phase: Int, Taggable {
        case methodSelection = 10
        case methodSelectionReply
        case request
        case requestReply
        
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
    struct MethodSelection: DataConvertible, Taggable {
        let numberOfAuthenticationMethods: UInt8
        let authenticationMethods: [AuthenticationMethod]
        
        init(data: Data) throws {
            var bytes: [UInt8] = [UInt8](repeating: 0, count: data.count)
            (data as NSData).getBytes(&bytes, length: bytes.count)
            
            guard bytes.count >= 3 else {
                throw SocketError.wrongNumberOfAuthenticationMethods
            }
            
            guard bytes[0] == Soxy.SOCKS.version else {
                throw SocketError.invalidSOCKSVersion
            }
            
            numberOfAuthenticationMethods = bytes[1]
            
            guard bytes.count == 1 + 1 + Int(numberOfAuthenticationMethods) else {
                throw SocketError.wrongNumberOfAuthenticationMethods
            }
            
            authenticationMethods = try bytes[2...(bytes.count - 1)].map() {
                guard let method = AuthenticationMethod(rawValue: $0) else {
                    throw SocketError.notSupportedAuthenticationMethod
                }
                return method
            }
        }
        
        var data: Data? {
            get {
                var bytes = [UInt8]()
                
                bytes.append(Soxy.SOCKS.version)
                bytes.append(numberOfAuthenticationMethods)
                bytes.append(contentsOf: authenticationMethods.map() { $0.rawValue })
                
                let data = Data(bytes: bytes)
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
    struct MethodSelectionReply: DataConvertible, Taggable {
        let method: AuthenticationMethod
        
        init(data: Data) throws {
            throw SocketError.notImplemented
        }
        
        init(method: AuthenticationMethod) {
            self.method = method
        }
        
        var data: Data? {
            get {
                let bytes = [Soxy.SOCKS.version, method.rawValue]
                return Data(bytes: bytes)
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
    struct Request: DataConvertible, Taggable {
        enum Command: UInt8 {
            case connect = 0x01
            case bind
            case udpAssociate
        }
        
        let command: Command
        let addressType: AddressType
        let targetHost: String
        let targetPort: UInt16
        
        init(data: Data) throws {
            var bytes = [UInt8](repeating: 0, count: data.count)
            (data as NSData).getBytes(&bytes, length: bytes.count)
            
            var offset = 0
            
            guard bytes[offset] == Soxy.SOCKS.version else {
                throw SocketError.invalidSOCKSVersion
            }
            offset += 1
            
            guard let cmd = Command(rawValue: bytes[offset]) else {
                throw SocketError.invalidRequestCommand
            }
            offset += 1
            command = cmd
            
            // Reserved
            _ = bytes[offset]
            offset += 1
            
            guard let atyp = AddressType(rawValue: bytes[offset]) else {
                throw SocketError.invalidAddressType
            }
            offset += 1
            addressType = atyp
            
            switch addressType {
            case .domainName:
                let domainNameLength = bytes[offset]
                offset += 1
                guard let domainName = String(bytes: bytes[offset..<(offset + Int(domainNameLength))], encoding: String.Encoding.ascii) else {
                    throw SocketError.invalidDomainName
                }
                targetHost = domainName
                offset += Int(domainNameLength)
                break
            default:
                targetHost = ""
                break
            }
            
            var bindPort: UInt16 = 0
            (data as NSData).getBytes(&bindPort, range: NSRange(location: offset, length: 2))
            targetPort = bindPort.bigEndian
        }
        
        var data: Data? {
            get {
                var bytes: [UInt8] = [Soxy.SOCKS.version, command.rawValue, Soxy.SOCKS.reserved, addressType.rawValue]
                
                switch addressType {
                case .domainName:
                    bytes.append(UInt8(targetHost.characters.count))
                    bytes.append(contentsOf: [UInt8](targetHost.utf8))
                    break
                default:
                    break
                }
                
                let bindPort = targetPort.littleEndian.byteSwapped
                bytes.append(contentsOf: bindPort.toByteArray())
                
                return Data(bytes: bytes)
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
        none = 0x00,
        gssapi,
        usernamePassword
    }
    
    enum AddressType: UInt8 {
        case ipv4 = 0x01
        case ipv6 = 0x04
        case domainName = 0x03
    }
    
    enum SocketError: Error {
        case invalidSOCKSVersion
        case unableToRetrieveNumberOfAuthenticationMethods
        case notSupportedAuthenticationMethod
        case supportedAuthenticationMethodNotFound
        case wrongNumberOfAuthenticationMethods
        case invalidRequestCommand
        case invalidHeaderFragment
        case invalidAddressType
        case invalidDomainLength
        case invalidDomainName
        case invalidPort
        case notImplemented
    }
    
/*
 +----+-----+-------+------+----------+----------+
 |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
 +----+-----+-------+------+----------+----------+
 | 1  |  1  | X'00' |  1   | Variable |    2     |
 +----+-----+-------+------+----------+----------+
*/
    struct Reply: DataConvertible, Taggable {
        enum Field: UInt8 {
            case succeed = 0x00
            case generalSOCKSServerFailure
            case connectionNotAllowedByRuleset
            case networkUnreachable
            case connectionRefused
            case ttlExpired
            case commandNotSupported
            case addressTypeNotSupported
        }
        let field: Field
        let addressType: AddressType
        let address: String
        let port: UInt16
        
        init(data: Data) throws {
            throw SocketError.notImplemented
        }
        
        init(field: Field, addressType: AddressType, address: String, port: UInt16) {
            self.field = field
            self.addressType = addressType
            self.address = address
            self.port = port
        }
        
        var data: Data? {
            get {
                var bytes: [UInt8] = [Soxy.SOCKS.version, field.rawValue, Soxy.SOCKS.reserved]
                
                // If reply field is anything other than Succeed, just reply with
                // VER, REP, RSV
                guard field == .succeed else {
                    return Data(bytes: bytes)
                }
                
                bytes.append(addressType.rawValue)
                
                switch addressType {
                case .domainName:
                    bytes.append(UInt8(address.characters.count))
                    bytes.append(contentsOf: [UInt8](address.utf8))
                    break
                default:
                    break
                }
                
                let data = NSMutableData(bytes: bytes, length: bytes.count)
                var networkOctetOrderPort: UInt16 = port.littleEndian
                data.append(&networkOctetOrderPort, length: 2)
                return data as Data
            }
        }
        
        var tag: Int {
            get {
                switch field {
                case .succeed:
                    return Connection.replyTag
                default:
                    return 0
                }
            }
        }
    }
    
    var delegate: ConnectionDelegate?
    var server: Proxyable?
    fileprivate let delegateQueue: DispatchQueue
    fileprivate let clientSocket: GCDAsyncSocket
    fileprivate var directSocket: GCDAsyncSocket?
    fileprivate var methodSelection: MethodSelection?
    fileprivate var request: Request?
    fileprivate var proxySocket: GCDAsyncSocket?
    
    open var hashValue: Int {
        get {
            return ObjectIdentifier(self).hashValue
        }
    }
    
    public static func ==(lhs: Connection, rhs: Connection) -> Bool {
        return ObjectIdentifier(lhs) == ObjectIdentifier(rhs)
    }
    
    init(socket: GCDAsyncSocket) {
        clientSocket = socket
        delegateQueue = DispatchQueue(label: "net.luosheng.SOCKSConnection.DelegateQueue", attributes: [])
        clientSocket.setDelegate(self, delegateQueue: delegateQueue)
        clientSocket.readData(Phase.methodSelection)
    }
    
    func disconnect() {
        clientSocket.disconnectAfterReadingAndWriting()
        directSocket?.disconnectAfterReadingAndWriting()
        proxySocket?.disconnectAfterReadingAndWriting()
    }
    
    // MARK: - Private methods
    
    fileprivate func processMethodSelection(_ data: Data) throws {
        let methodSelection = try MethodSelection(data: data)
        guard methodSelection.authenticationMethods.contains(.none) else {
            throw SocketError.supportedAuthenticationMethodNotFound
        }
        self.methodSelection = methodSelection
        let reply = MethodSelectionReply(method: .none)
        clientSocket.writeData(reply)
        clientSocket.readData(Phase.request)
    }
    
    fileprivate func processRequest(_ data: Data) throws {
        let request = try Request(data: data)
        let reply = Reply(field: .succeed, addressType: request.addressType, address: request.targetHost, port: request.targetPort)
        self.request = request
        clientSocket.writeData(reply)
        clientSocket.readData(withTimeout: -1, tag: 0)
    }
    
    // MARK: - GCDAsyncSocketDelegate
    
    @objc open func socketDidDisconnect(_ sock: GCDAsyncSocket, withError err: Error?) {
        disconnect()
        delegate?.connectionDidClose(self)
    }

    @objc open func socket(_ sock: GCDAsyncSocket, didRead data: Data, withTag tag: Int) {
        do {
            guard let phase = Phase(rawValue: tag) else {
                // If the tag is not specified, it's in proxy mode
                if sock == clientSocket {
                    if server?.proxyServer != nil {
                        proxySocket?.write(data, withTimeout: -1, tag: 0)
                    } else {
                        directSocket?.write(data, withTimeout: -1, tag: 0)
                    }
                } else {
                    clientSocket.write(data, withTimeout: -1, tag: 0)
                }
                sock.readData(withTimeout: -1, tag: 0)
                return
            }
            switch phase {
            case .methodSelection:
                try self.processMethodSelection(data)
                break
            case .request:
                try self.processRequest(data)
                break
            case .methodSelectionReply:
                if let request = request {
                    proxySocket?.writeData(request)
                    proxySocket?.readData(Phase.requestReply)
                }
                break
            case .requestReply:
                clientSocket.readData(withTimeout: -1, tag: 0)
                proxySocket?.readData(withTimeout: -1, tag: 0)
                break
            }
        } catch {
            print("error: \(error)")
            self.disconnect()
        }
    }
    
    @objc open func socket(_ sock: GCDAsyncSocket, didWriteDataWithTag tag: Int) {
        if tag == Connection.replyTag {
            
            if let proxyServer = server?.proxyServer {
                proxySocket = GCDAsyncSocket(delegate: self, delegateQueue: delegateQueue)
                try! proxySocket?.connect(toHost: proxyServer.address, onPort: UInt16(proxyServer.port))
                if let methodSelection = methodSelection {
                    proxySocket?.writeData(methodSelection)
                    proxySocket?.readData(Phase.methodSelectionReply)
                }
            } else {
                directSocket = GCDAsyncSocket(delegate: self, delegateQueue: delegateQueue)
                guard let request = request else {
                    return
                }
                do {
                    try directSocket?.connect(toHost: request.targetHost, onPort: request.targetPort, withTimeout: -1)
                    clientSocket.readData(withTimeout: -1, tag: 0)
                    directSocket?.readData(withTimeout: -1, tag: 0)
                } catch {
                    clientSocket.disconnectAfterReadingAndWriting()
                }
            }
        }
    }
}
