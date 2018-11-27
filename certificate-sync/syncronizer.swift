//
//  syncronizer.swift
//  certificate-sync
//
//  Created by Rick Mark on 11/22/18.
//  Copyright © 2018 Dropbox. All rights reserved.
//

import Foundation

class Syncronizer {
    let configuration: Configuration
    
    init(configuration: Configuration) {
        self.configuration = configuration
    }
    
    func run() {
        let identities = mapIdentities()
        
        for (_, identity) in identities {
            ensureSelfInOwnerACL(identity: identity)
        }
    }
    
    func getKeychains() -> [ String: SecKeychain ] {
        var result = [ String : SecKeychain ]()
        
        for item in configuration.items {
            var keychain: SecKeychain?
            assert(SecKeychainOpen(item.keychainPath, &keychain) == kOSReturnSuccess)
            
            if result.keys.contains(item.keychainPath) == false {
                var keychain: SecKeychain?
                
                assert(SecKeychainOpen(item.keychainPath, &keychain) == kOSReturnSuccess)
                
                result[item.keychainPath] = keychain!
            }
        }
        
        return result
    }
    
    func mapIdentities() -> [ ( ConfigurationItem, SecIdentity ) ] {
        var results = [ (ConfigurationItem, SecIdentity ) ]()
        
        for (path, keychain) in getKeychains() {
            
            let query = [kSecClass: kSecClassIdentity,
                         kSecReturnRef: true,
                         kSecMatchLimit: kSecMatchLimitAll,
                         kSecReturnAttributes: true,
                         kSecUseKeychain: keychain] as CFDictionary
            
            var items: CFTypeRef?
            
            assert(SecItemCopyMatching(query, &items) == kOSReturnSuccess)

            for identityItem in (items! as! [[String: Any]]) {
                let identityIssuer = identityItem[kSecAttrIssuer as String] as! NSData
                
                let configurationItems = configuration.items.filter { (item) -> Bool in
                    return item.issuer == identityIssuer as Data
                }
                
                for configurationItem in configurationItems.filter({ (configurationItem) -> Bool in
                    configurationItem.keychainPath == path
                }) {
                    let tuple = ( configurationItem, identityItem[kSecValueRef as String] as! SecIdentity )
                    results.append(tuple)
                }
            }
        }
        
        return results
    }
    
    func trustedApplicationForSelf() -> SecTrustedApplication {
        var trustedApplication: SecTrustedApplication?
        
        let createResult = SecTrustedApplicationCreateFromPath(CommandLine.arguments.first!, &trustedApplication)
        
        assert(createResult == kOSReturnSuccess)
        assert(trustedApplication != nil)
        
        return trustedApplication!
    }
    
    func ensureSelfInOwnerACL(identity: SecIdentity) {
        var access: SecAccess?
        
        var privateKey: SecKey?
        SecIdentityCopyPrivateKey(identity, &privateKey)
        
        assert(privateKey != nil)
        let privateKeyItem = (privateKey as Any) as! SecKeychainItem
        
        assert(SecKeychainItemCopyAccess(privateKeyItem, &access) == kOSReturnSuccess)
        assert(access != nil)
        
        var aclEntriesArray: CFArray?
        assert(SecAccessCopyACLList(access!, &aclEntriesArray) == kOSReturnSuccess)
        
        for aclEntry in aclEntriesArray as! [ SecACL ] {
            var applicationListArray: CFArray?
            var description: CFString?
            var promptSelector = SecKeychainPromptSelector.init(rawValue: 0)
            
            SecACLCopyContents(aclEntry, &applicationListArray, &description, &promptSelector)
            
            let authorizations = SecACLCopyAuthorizations(aclEntry) as? [ SecACL ]
            
            print(authorizations)
        }
    }
}
