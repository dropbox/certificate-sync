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
                
                assert(SecKeychainOpen(item.keychainPath.toUnixPath(), &keychain) == kOSReturnSuccess)
                
                var keychainStatus = SecKeychainStatus()
                assert(SecKeychainGetStatus(keychain!, &keychainStatus) == kOSReturnSuccess)
                
                if ((keychainStatus & kSecUnlockStateStatus) == 0) {
                    if item.password != nil {
                        assert(SecKeychainUnlock(keychain!, UInt32(item.password!.count), item.password!, true) == kOSReturnSuccess)
                    }
                    else {
                        assert(SecKeychainUnlock(keychain!, 0, "", false) == kOSReturnSuccess)
                    }
                }
                
                assert(SecKeychainGetStatus(keychain!, &keychainStatus) == kOSReturnSuccess)
                assert((keychainStatus & kSecUnlockStateStatus > 0) && (keychainStatus & kSecReadPermStatus > 0) && (keychainStatus & kSecWritePermStatus > 0))
                
                result[item.keychainPath] = keychain!
            }
        }
        
        return result
    }
    
    func mapIdentities() -> [ ( configuration: ConfigurationItem, identity: SecIdentity ) ] {
        var results = [ (ConfigurationItem, SecIdentity ) ]()
        
        for (path, keychain) in getKeychains() {
            
            let query = [kSecClass: kSecClassIdentity,
                         kSecReturnRef: true,
                         kSecMatchLimit: kSecMatchLimitAll,
                         kSecReturnAttributes: true,
                         kSecMatchSearchList: [ keychain ]
                ] as CFDictionary
            
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
    
//    func ensureAppsInACL(identity: SecIdentity, aclEntries: [ ACLConfigurationItem ]) {
//        var aclEntryList = getSecAccessForIdentity(identity: identity)
//
//        let appsToAdd = aclEntries.reduce([ Data, SecTrustedApplication ]() { (results, item) -> [ Data : SecTrustedApplication ] in
//            var trustedApplication: SecTrustedApplication?
//            var applicationData: CFData?
//
//            assert(SecTrustedApplicationCreateFromPath(item.path, &trustedApplication) == kOSReturnSuccess)
//
//            assert(SecTrustedApplicationCopyData(trustedApplication!, &applicationData) == kOSReturnSuccess)
//
//            results[(applicationData! as Data)] = trustedApplication!
//        }
//
//        var applicationIndex = aclEntryList.flatMap { (acl) -> [ ( SecTrustedApplication, Data ) ] in
//            var applicationListArray: CFArray?
//            var description: CFString?
//            var promptSelector = SecKeychainPromptSelector.init(rawValue: 0)
//
//            SecACLCopyContents(acl, &applicationListArray, &description, &promptSelector)
//
//            return (applicationListArray as! [ SecTrustedApplication ]).map({ (trustedApplication) -> (SecTrustedApplication, Data) in
//                var data: CFData?
//
//                SecTrustedApplicationCopyData(trustedApplication, &data)
//
//                return (trustedApplication, data! as Data)
//            })
//        }
//
//        for entry in applicationIndex {
//            let application = applicationIndex[entry.1]
//
//            if application == nil {
//
//
//
//            }
//        }
//    }
    
    private func getSecAccessForIdentity(identity: SecIdentity, access: inout SecAccess?) -> [ SecACL ] {
        var privateKey: SecKey?
        SecIdentityCopyPrivateKey(identity, &privateKey)
        
        assert(privateKey != nil)
        let privateKeyItem = (privateKey as Any) as! SecKeychainItem
        
        assert(SecKeychainItemCopyAccess(privateKeyItem, &access) == kOSReturnSuccess)
        assert(access != nil)
        
        var aclEntriesArray: CFArray?
        
        assert(SecAccessCopyACLList(access!, &aclEntriesArray) == kOSReturnSuccess)
        
        return aclEntriesArray as! [ SecACL ]
    }
    
    func ensureSelfInOwnerACL(identity: SecIdentity) {
        var access: SecAccess?
        
        let aclEntriesArray = getSecAccessForIdentity(identity: identity, access: &access)
        
        let selfTrustedApplication = trustedApplicationForSelf()
        
        var updateACL = false
        
        for aclEntry in aclEntriesArray {
            var applicationListArray: CFArray?
            var description: CFString?
            var promptSelector = SecKeychainPromptSelector.init(rawValue: 0)
            
            SecACLCopyContents(aclEntry, &applicationListArray, &description, &promptSelector)
            var authorizationArray = SecACLCopyAuthorizations(aclEntry) as! [ CFString ]
            
            if applicationListArray == nil {
                applicationListArray = NSArray()
            }
            
            var applicationList = applicationListArray as! [ SecTrustedApplication ]
            
            if authorizationArray.contains(kSecACLAuthorizationChangeACL)
                && applicationList.contains(selfTrustedApplication) == false  {

                applicationList.append(selfTrustedApplication)

                let authorizationUpdate = SecACLUpdateAuthorizations(aclEntry, applicationList as CFArray)
                assert(authorizationUpdate == kOSReturnSuccess)
                
                let setContents = SecACLSetContents(aclEntry, applicationList as CFArray, description!, promptSelector)
                assert(setContents == kOSReturnSuccess)
                
                continue
            }
            

            
            
            
            
//
//            if applicationList.contains(selfTrustedApplication) {
//                applicationList.append(selfTrustedApplication)
//                assert(SecACLSetContents(aclEntry, applicationList as CFArray, description!, promptSelector) == kOSReturnSuccess)
//            }
//
//            if updateACL {
//                SecKeychainItemSetAccess(identity as! SecKeychainItem, access!)
//            }
//
//
//
//            if authorizationArray.contains(kSecACLAuthorizationExportClear) == false {
//                authorizationArray.append(kSecACLAuthorizationExportClear)
//                updateACL = true
//            }
//            if authorizationArray.contains(kSecACLAuthorizationExportWrapped) == false {
//                authorizationArray.append(kSecACLAuthorizationExportWrapped)
//                updateACL = true
//            }
//
//            if updateACL {
//                let result = SecACLUpdateAuthorizations(aclEntry, authorizationArray as CFArray)
//                assert(result == kOSReturnSuccess)
//            }
        }
    }
    
    func exportKeychainItems(items: [ ( configuration: ConfigurationItem, identity: SecIdentity ) ]) {
        for item in items {
            for export in item.configuration.exports {
                var exportParameters = SecItemImportExportKeyParameters.init()
                let exportFlags = export.pemEncode ? SecItemImportExportFlags.pemArmour : SecItemImportExportFlags.init(rawValue: 0)
                
                var exportData: CFData?
                
                if export.format == .formatPEMSequence {
                    var privateKey: SecKey?
                    
                    assert(SecIdentityCopyPrivateKey(item.identity, &privateKey) == kOSReturnSuccess)
                    let result = SecItemExport(privateKey!, export.format, exportFlags, &exportParameters, &exportData)
                    assert(result == kOSReturnSuccess)
                }
                if export.format == .formatX509Cert {
                    var certificate: SecCertificate?
                    
                    assert(SecIdentityCopyCertificate(item.identity, &certificate) == kOSReturnSuccess)
                    let result = SecItemExport(certificate!, export.format, exportFlags, &exportParameters, &exportData)
                    assert(result == kOSReturnSuccess)
                }
                
                let exportedData = exportData as NSData?
                exportedData!.write(to: export.path, atomically: true)
            }
        }
    }
}
