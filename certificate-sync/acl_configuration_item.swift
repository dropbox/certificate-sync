//
//  File.swift
//  certificate-sync
//
//  Created by Rick Mark on 11/22/18.
//  Copyright © 2018 Dropbox. All rights reserved.
//

import Foundation
import AppKit

class ACLConfigurationItem {
    static let bundlePrefix = "bundle:"
    let bundleId: String?
    let path: String
    
    init(fromPath : String) {
        bundleId = nil
        path = fromPath.toUnixPath()
    }
    
    init(fromPath : String, bundleId: String) {
        self.bundleId = bundleId
        path = fromPath.toUnixPath()
    }
    
    static func parse(configuration: String) -> [ ACLConfigurationItem ] {
        if configuration.starts(with: bundlePrefix) == false {
            return [ ACLConfigurationItem(fromPath: configuration) ]
        }
        
        let prefixIndex = configuration.index(after: configuration.firstIndex(of: ":")!)
        let bundleId = String(configuration[prefixIndex...])
        
        var error: Unmanaged<CFError>?
        
        let appBundles = LSCopyApplicationURLsForBundleIdentifier(bundleId as CFString, &error)?.takeRetainedValue()
        
        if appBundles == nil {
            return []
        }
        
        return (appBundles as! [ URL ]).map { (appBundle) -> ACLConfigurationItem in
            ACLConfigurationItem(fromPath: appBundle.path, bundleId: bundleId)
        }
    }
    
    func trustedAppliction() -> SecTrustedApplication {
        var trustedApplication: SecTrustedApplication?
        
        let createResult = SecTrustedApplicationCreateFromPath(self.path, &trustedApplication)
        
        assert(createResult == kOSReturnSuccess)
        assert(trustedApplication != nil)
        
        return trustedApplication!
    }
}
