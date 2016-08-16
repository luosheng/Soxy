//
//  AppDelegate.swift
//  S5
//
//  Created by Luo Sheng on 15/10/1.
//  Copyright © 2015年 Pop Tap. All rights reserved.
//

import Cocoa
import NetworkExtension

@NSApplicationMain
class AppDelegate: NSObject, NSApplicationDelegate {

    @IBOutlet weak var window: NSWindow!
    
    let server: Server
    
    override init() {
        server = try! Server(port: 8080)
        server.proxyServer = NEProxyServer(address: "127.0.0.1", port: 1080)
        print(server.host, server.port)
        super.init()
    }

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        // Insert code here to initialize your application
    }

    func applicationWillTerminate(_ aNotification: Notification) {
        // Insert code here to tear down your application
    }


}

