//
//  ImportItem.swift
//  certificate-sync
//
//  Created by Rick Mark on 12/11/18.
//  Copyright © 2018 Dropbox. All rights reserved.
//

import Foundation

class ImportItem {
    let issuer: Data
    let acls: [ACLConfigurationItem]
    let claimOwner: Bool
    let keychainPath: String
    
    init(issuer: Data, aclEntries: [ ACLConfigurationItem ], claimOwner: Bool, keychainPath: String) {
        self.issuer = issuer
        self.acls = aclEntries
        self.claimOwner = claimOwner
        self.keychainPath = keychainPath
    }
    
    static func parse(configuration: [ String : Any ]) -> ImportItem {
        let issuer = Data(base64Encoded: configuration["issuer"] as! String)!
        let claimOwner = configuration["claim_owner"] as? Bool ?? true
        var keychainPath: String!
        let keychainValue = configuration["keychain"] as? String ?? "system"
        
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
        
        return ImportItem(issuer: issuer, aclEntries: acls, claimOwner: claimOwner, keychainPath: keychainPath)
    }
}
