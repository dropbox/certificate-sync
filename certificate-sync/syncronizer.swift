//
//  syncronizer.swift
//  certificate-sync
//
//  Created by Rick Mark on 11/22/18.
//  Copyright © 2018 Dropbox. All rights reserved.
//

import Foundation

class Syncronizer {
    func mapIdentities(configuration: Configuration) -> [ ( ConfigurationItem, SecIdentity ) ] {
        let query = [kSecClass: kSecClassIdentity,
                     kSecReturnRef: true,
                     kSecMatchLimit: kSecMatchLimitAll,
                     kSecReturnAttributes: true] as CFDictionary
        
        var items: CFTypeRef?
        
        assert(SecItemCopyMatching(query, &items) == kOSReturnSuccess)
        
        var results = [ (ConfigurationItem, SecIdentity ) ]()

        for identityItem in (items! as! [[String: Any]]) {
            let identityIssuer = identityItem[kSecAttrIssuer as String] as! NSData
            
            let configurationItems = configuration.items.filter { (item) -> Bool in
                item.issuer == identityIssuer as Data
            }
            
            for configurationItem in configurationItems {
                let tuple = ( configurationItem, identityItem[kSecValueRef as String] as! SecIdentity )
                results.append(tuple)
            }
        }
        
        return results
    }
}
