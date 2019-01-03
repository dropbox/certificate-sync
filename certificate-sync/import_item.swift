//
//  ImportItem.swift
//  certificate-sync
//
//  Created by Rick Mark on 12/11/18.
//  Copyright © 2018 Dropbox. All rights reserved.
//

import Foundation

class ImportItem {
    let path: URL
    let acls: [ ACLConfigurationItem ]
    let claimOwner: Bool
    let keychainPath: String
    let password: String?
    let label: String?
    
    init(label: String?, path: URL, aclEntries: [ ACLConfigurationItem ], claimOwner: Bool, keychainPath: String, password: String?) {
        self.label = label
        self.path = path
        self.acls = aclEntries
        self.claimOwner = claimOwner
        self.keychainPath = keychainPath
        self.password = password
    }
    
    static func parse(configuration: [ String : Any ]) -> ImportItem {
        let label = configuration["label"] as? String
        let path = URL(fileURLWithPath: configuration["path"] as! String)
        let claimOwner = configuration["claim_owner"] as? Bool ?? false
        var keychainPath: String!
        let keychainValue = configuration["keychain"] as? String ?? "system"
        let password = configuration["password"] as? String
        
        switch keychainValue {
        case "system":
            keychainPath = "/Library/Keychains/System.keychain"
        case "user":
            keychainPath = ("~/Library/Keychains/login.keychain" as NSString).expandingTildeInPath
        default:
            keychainPath = keychainValue
        }
        
        let acls = (configuration["acl"] as? [ String ] ?? []).flatMap { (item) -> [ ACLConfigurationItem ] in
            return ACLConfigurationItem.parse(configuration: item)
        }
        
        return ImportItem(label: label, path: path, aclEntries: acls, claimOwner: claimOwner, keychainPath: keychainPath, password: password)
    }
}
