//
//  syncronizer.swift
//  certificate-sync
//
//  Created by Rick Mark on 11/22/18.
//  Copyright © 2018 Dropbox. All rights reserved.
//

import Foundation

class Syncronizer {
    let privateKeyACLDescription = "com.dropbox.certificate-sync.acl"
    
    let requiredAuthorization = [ kSecACLAuthorizationSign,
                                  kSecACLAuthorizationMAC,
                                  kSecACLAuthorizationDerive,
                                  kSecACLAuthorizationDecrypt ]
    
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

    
    func ensureSelfInOwnerACL(identity: SecIdentity) {
        var access: SecAccess?
        var privateKey: SecKey?
        
        assert(SecIdentityCopyPrivateKey(identity, &privateKey) == kOSReturnSuccess)
        assert(privateKey != nil)
        
        let privateKeyItem = (privateKey as Any) as! SecKeychainItem
        
        assert(SecKeychainItemCopyAccess(privateKeyItem, &access) == kOSReturnSuccess)
        assert(access != nil)

        
        let selfTrustedApplication = trustedApplicationForSelf()
        
        let aclResults = SecAccessCopyMatchingACLList(access!, kSecACLAuthorizationChangeACL)
        
        let acls = aclResults as! [ SecACL ]
        
        for acl in acls {
            var applicationList: CFArray?
            var description: CFString?
            var promptSelector = SecKeychainPromptSelector()
            
            assert(SecACLCopyContents(acl, &applicationList, &description, &promptSelector) == kOSReturnSuccess)
            
            if description == nil {
                description = "" as CFString
            }

            applicationList = updateApplicationList(existing: applicationList, applications: [ selfTrustedApplication ])
            
            assert(SecACLSetContents(acl, applicationList! as CFArray, description!, promptSelector) == kOSReturnSuccess)

            assert(SecKeychainItemSetAccess(privateKeyItem, access!) == kOSReturnSuccess)
        }
    }
    
    private func updateApplicationList(existing: CFArray?, applications: [ SecTrustedApplication ]) -> CFArray {
        var applicationListArray = existing == nil ? [ SecTrustedApplication ]() : existing as! [ SecTrustedApplication ]
        
        let existingApplicationData = applicationListArray.map { (item) -> Data in
            var data: CFData?
            
            assert(SecTrustedApplicationCopyData(item, &data) == kOSReturnSuccess)
            
            return data! as Data
        }
        
        for applicationToAdd in applications {
            var data: CFData?
            
            assert(SecTrustedApplicationCopyData(applicationToAdd, &data) == kOSReturnSuccess)
            
            let castData = data! as Data
            
            if existingApplicationData.contains(castData) == false {
                applicationListArray.append(applicationToAdd)
            }
        }
        
        return applicationListArray as CFArray
    }
    
    func ensureACLContainsApps(items: [ ( configuration: ConfigurationItem, identity: SecIdentity ) ]) {
        for item in items {
            var privateKey: SecKey?
            var access: SecAccess?
            var aclListArray: CFArray?

            assert(SecIdentityCopyPrivateKey(item.identity, &privateKey) == kOSReturnSuccess)
            assert(privateKey != nil)
            
            let privateKeyItem = (privateKey as Any) as! SecKeychainItem
            
            assert(SecKeychainItemCopyAccess(privateKeyItem, &access) == kOSReturnSuccess)
            assert(access != nil)
            
            assert(SecAccessCopyACLList(access!, &aclListArray) == kOSReturnSuccess)
            assert(aclListArray != nil)
            let acls = aclListArray as! [ SecACL ]
            
            var foundACL = false
            
            for acl in acls {
                var applicationListArray: CFArray?
                var descriptionString: CFString?
                var promptSelector = SecKeychainPromptSelector()
                
                assert(SecACLCopyContents(acl, &applicationListArray, &descriptionString, &promptSelector) == kOSReturnSuccess)
                
                let description = descriptionString as String?
                
                if description != privateKeyACLDescription { continue }
                
                foundACL = true
                
                let applications = item.configuration.acls.map { (acl) -> SecTrustedApplication in
                    return acl.trustedAppliction
                }

                applicationListArray = updateApplicationList(existing: applicationListArray, applications: applications)

                var authorizations = SecACLCopyAuthorizations(acl) as! [ CFString ]
                
                for authorization in requiredAuthorization {
                    if authorizations.contains(authorization) == false {
                        authorizations.append(authorization)
                    }
                }
                
                assert(SecACLUpdateAuthorizations(acl, authorizations as CFArray) == kOSReturnSuccess)
                
                assert(SecACLSetContents(acl, applicationListArray, description! as CFString, promptSelector) == kOSReturnSuccess)
            }
            
            if foundACL == false {
                var acl: SecACL?
                let promptSelector = SecKeychainPromptSelector()
                
                let applications = item.configuration.acls.map { (item) -> SecTrustedApplication in
                    item.trustedAppliction
                } as CFArray
                
                assert(SecACLCreateWithSimpleContents(access!, applications, privateKeyACLDescription as CFString, promptSelector, &acl) == kOSReturnSuccess)
                assert(acl != nil)
                
                let authorizations = requiredAuthorization as CFArray
                
                assert(SecACLUpdateAuthorizations(acl!, authorizations) == kOSReturnSuccess)
            }
            
            assert(SecKeychainItemSetAccess(privateKeyItem, access!) == kOSReturnSuccess)
        }
    }
    
    func exportKeychainItems(items: [ ( configuration: ConfigurationItem, identity: SecIdentity ) ]) {
        for item in items {
            for export in item.configuration.exports {
                var exportParameters = SecItemImportExportKeyParameters.init()
                let exportFlags = export.pemEncode ? SecItemImportExportFlags.pemArmour : SecItemImportExportFlags()
                
                var exportData: CFData?
                
                if export.password != nil {
                    let passwordData = Unmanaged<CFTypeRef>.passRetained(export.password! as CFTypeRef)
                    exportParameters.passphrase = passwordData
                }
                
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
                
                // TODO: Set owner
                // TODO: Set mode
            }
        }
    }
}
