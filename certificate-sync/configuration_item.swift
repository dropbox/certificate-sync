//
//  configuration_item.swift
//  certificate-sync
//
//  Created by Rick Mark on 11/21/18.
//  Copyright © 2018 Dropbox. All rights reserved.
//

import Foundation

class ConfigurationItem {
    let issuer: Data
    let exports: [ExportConfigurationItem]
    let acls: [ACLConfigurationItem]
    let keychainPath: String
    
    init(issuer: Data, exports: [ExportConfigurationItem], acls: [ACLConfigurationItem], keychainPath: String) {
        self.issuer = issuer
        self.exports = exports
        self.acls = acls
        self.keychainPath = keychainPath
    }

    static func parse(configuration : [ String : Any ]) -> ConfigurationItem {
        let issuer = Data(base64Encoded: configuration["issuer"] as! String)!
        var keychainPath: String!
        let keychainValue = configuration["keychain"] as! String
        
        switch keychainValue {
        case "system":
            keychainPath = "/Library/Keychains/System.keychain"
        case "user":
            keychainPath = ("~/Library/Keychains/login.keychain" as NSString).expandingTildeInPath
        default:
            keychainPath = keychainValue
        }
        
        
        let exports = (configuration["export"] as! [ [ String : Any ] ]).map { (item) -> ExportConfigurationItem in
            return ExportConfigurationItem.parse(configuration: item)
        }
        
        let acls = (configuration["acl"] as! [ String ]).flatMap { (item) -> [ ACLConfigurationItem ] in
            return ACLConfigurationItem.parse(configuration: item)
        }
        
        return ConfigurationItem(issuer: issuer, exports: exports, acls: acls, keychainPath: keychainPath)
    }
}
