//
//  GCDAsyncSocketExtensions.swift
//  Soxy
//
//  Created by Luo Sheng on 17/08/2016.
//  Copyright © 2016 Pop Tap. All rights reserved.
//

import Foundation
import CocoaAsyncSocket

extension GCDAsyncSocket {
    func writeData<T>(_ t: T) where T: NSDataConvertible, T: Taggable {
        if let data = t.data {
            self.write(data, withTimeout: -1, tag: t.tag)
        }
    }
    
    func readData<T>(_ t: T) where T: Taggable {
        self.readData(withTimeout: -1, tag: t.tag)
    }
}
