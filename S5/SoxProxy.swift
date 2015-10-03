//
//  SoxProxy.swift
//  SoxProxy
//
//  Created by Luo Sheng on 15/10/3.
//  Copyright © 2015年 Pop Tap. All rights reserved.
//

import Foundation

protocol NSDataConvertible {
    init(data: NSData) throws
    var data: NSData? { get }
}