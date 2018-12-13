//
//  test_suite.swift
//  test-suite
//
//  Created by Rick Mark on 11/26/18.
//  Copyright © 2018 Dropbox. All rights reserved.
//

import XCTest


class test_suite: XCTestCase {
    
    var testConfiguration: URL!
    let tempDirectoryURL = NSURL.fileURL(withPath: NSTemporaryDirectory(), isDirectory: true)
    let tag = "com.dropbox.entsec.certificate-sync.tests"

    override func setUp() {
        let selfBundle = Bundle(for: type(of: self))
        testConfiguration = selfBundle.url(forResource: "test_configuration", withExtension: "plist")
        
        FileManager.default.changeCurrentDirectoryPath(tempDirectoryURL.absoluteString.toUnixPath())
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    private func getKeychainCopy() -> (URL, SecKeychain) {
        let tempKeychainFile = tempDirectoryURL.appendingPathComponent("\(UUID().uuidString)-demo.keychain")
        print(tempKeychainFile)

        var keychain: SecKeychain?
        assert(SecKeychainCreate(tempKeychainFile.absoluteString.toUnixPath(), 0, "", false, nil, &keychain) == kOSReturnSuccess)
        
        var privateKey: SecKey!
        var publicKey: SecKey!
        
        let generationAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ],
            kSecPublicKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ]
        ]
        
        assert(SecKeyGeneratePair(generationAttributes as CFDictionary, &publicKey, &privateKey) == kOSReturnSuccess)
        
        let storePublicKey: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: "\(tag).public".data(using: .utf8)!,
            kSecValueRef as String: publicKey!,
            kSecUseKeychain as String: keychain!
        ]
        
        let storePrivateKey: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecValueRef as String: privateKey!,
            kSecUseKeychain as String: keychain!
        ]
        
        var publicKeyResult: CFTypeRef?
        var privateKeyResult: CFTypeRef?
        
        assert(SecItemAdd(storePublicKey as CFDictionary, &publicKeyResult) == kOSReturnSuccess)
        assert(SecItemAdd(storePrivateKey as CFDictionary, &privateKeyResult) == kOSReturnSuccess)
        
        privateKey = (privateKeyResult! as! SecKey)
        publicKey = (publicKeyResult! as! SecKey)
        
        var privateKeyPem: CFData?
        var exportKeyParameters = SecItemImportExportKeyParameters()
        
        assert(SecItemExport(privateKey, SecExternalFormat.formatPEMSequence, SecItemImportExportFlags(), &exportKeyParameters, &privateKeyPem) == kOSReturnSuccess)
        
        var privateKeyMarshaledData = privateKeyPem! as Data
        
        let keyBasicIO = privateKeyMarshaledData.withUnsafeBytes { (data) -> UnsafeMutablePointer<BIO>? in
            return BIO_new_mem_buf(data, Int32(privateKeyMarshaledData.count))
        }
        
        let openSSLPrivateKey = PEM_read_bio_PrivateKey(keyBasicIO!, nil, nil, nil)
        
        BIO_free(keyBasicIO)
        
        assert(openSSLPrivateKey != nil)
        
        let certificate = X509_new()
        
        assert(X509_set_version(certificate, 2) == 1)
        assert(ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1) == 1)
        
        let currentTime = timegm(nil)
        var notBefore = ASN1_TIME()
        var notAfter = ASN1_TIME()
       
        assert(ASN1_TIME_set(&notBefore, currentTime) != nil)
        assert(ASN1_TIME_adj(&notAfter, currentTime, 365, 0) != nil)
        
        assert(X509_set_notBefore(certificate!, &notBefore) == 1)
        assert(X509_set_notAfter(certificate!, &notAfter) == 1)
        
        let name = X509_NAME_new()
        
        assert(X509_NAME_add_entry_by_txt(name, "CN", V_ASN1_IA5STRING, "Self Signed Test Certificate", -1, -1, 0) == 1)
        
        assert(X509_set_subject_name(certificate!, name) == 1)
        assert(X509_set_issuer_name(certificate!, name) == 1)
        
        assert(X509_set_pubkey(certificate!, openSSLPrivateKey) == 1)
        
        assert(X509_sign(certificate!, openSSLPrivateKey, EVP_sha256()) != 0)
        
        let certificatePEM = BIO_new(BIO_s_mem())
        
        assert(PEM_write_bio_X509(certificatePEM, certificate!) != 0)
        
        var data: UnsafeMutableRawPointer?
        let dataSize = BIO_ctrl(certificatePEM, BIO_CTRL_INFO, 0, &data)
        
        assert(dataSize > 0)
        assert(data != nil)
        
        let certificateData = Data(bytes: data!, count: dataSize)
        
        X509_NAME_free(name)
        X509_free(certificate)
        EVP_PKEY_free(openSSLPrivateKey)
        
        BIO_free(certificatePEM)

        var certificateImportResults: CFArray?
        var importItemType = SecExternalItemType.itemTypeCertificate
        assert(SecItemImport(certificateData as CFData, nil, nil, &importItemType, SecItemImportExportFlags(rawValue: 0), nil, keychain!, &certificateImportResults) == kOSReturnSuccess)
        
        var identity: SecIdentity?
        let certificateKeychainItem = (certificateImportResults as! [ SecCertificate ]).first!
        assert(SecIdentityCreateWithCertificate(keychain!, certificateKeychainItem, &identity) == kOSReturnSuccess)
        
        return (tempKeychainFile, keychain!)
    }
    
    private func modifyConfigurationForDemoKeychain(configuration: Configuration, demoKeychainPath: URL, issuer: Data) -> Configuration {
        let mapping = configuration.existing.map { (item) -> ConfigurationItem in
            if item.keychainPath == "demo.keychain" {
                return ConfigurationItem(issuer: issuer, exports: item.exports, acls: item.acls, keychainPath: demoKeychainPath.absoluteString, password: item.password, claimOwner: item.claimOwner)
            }
            else {
                return item
            }
        }
        
        let selfBundle = Bundle(for: type(of: self))
        let imports = configuration.imports.map { (item) -> ImportItem in
            let path = selfBundle.resourceURL?.appendingPathComponent(item.path.lastPathComponent)
            
            if item.keychainPath == "demo.keychain" {
                return ImportItem(path: path!, aclEntries: item.acls, claimOwner: item.claimOwner, keychainPath: demoKeychainPath.absoluteString, password: item.password)
            }
            else {
                return item
            }
        }
        
        return Configuration(aclName: configuration.aclName, existing: mapping, imports: imports)
    }
    
    private func getCertificateIssuer(keychain: SecKeychain) -> Data {
        let certificateQuery: [String : Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecMatchSearchList as String: [ keychain ],
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnAttributes as String: true
        ]
        
        var resultItem: CFTypeRef?
        assert(SecItemCopyMatching(certificateQuery as CFDictionary, &resultItem) == kOSReturnSuccess)
        assert(resultItem != nil)
        
        let resultDictionaryArray = resultItem as! [ String: Any ]
        
        return resultDictionaryArray[kSecAttrIssuer as String] as! Data
    }

    func testLoadConfiguration() {
        let _ = Configuration.read(path: testConfiguration)
    }
    
    func testImportItems() {
        let (keychainCopy, keychain) = getKeychainCopy()
        let issuer = getCertificateIssuer(keychain: keychain)
        
        let configuration = modifyConfigurationForDemoKeychain(configuration: Configuration.read(path: testConfiguration), demoKeychainPath: keychainCopy, issuer: issuer)
        
        let syncronizer = Syncronizer(configuration: configuration)
        
        let itemCount = countKeychainItems(keychain: keychain, type: kSecClassKey)
        
        syncronizer.importKeychainItems(items: configuration.imports)
        
        assert(countKeychainItems(keychain: keychain, type: kSecClassKey) == itemCount + 1)
    }
    
    private func countKeychainItems(keychain: SecKeychain, type: CFString) -> Int {
        var result: CFTypeRef?
        
        let query = [ kSecClass : kSecClassKey,
                      kSecMatchLimit : kSecMatchLimitAll,
                      kSecMatchSearchList : [ keychain ],
                      kSecReturnAttributes : true ] as [CFString : Any]
        
        assert(SecItemCopyMatching(query as CFDictionary, &result) == kOSReturnSuccess)
        
        let resultsArray = result as! [ SecKey ]
        
        return resultsArray.count
    }

    func testMapIdentities() {
        let (keychainCopy, keychain) = getKeychainCopy()
        
        let issuer = getCertificateIssuer(keychain: keychain)
        let configuration = modifyConfigurationForDemoKeychain(configuration: Configuration.read(path: testConfiguration), demoKeychainPath: keychainCopy, issuer: issuer)
        
        let syncronizer = Syncronizer(configuration: configuration)
        
        let results = syncronizer.mapIdentities()
        
        assert(results.count == 1)
        
        let itemCount = countKeychainItems(keychain: keychain, type: kSecClassKey)
        
        assert(itemCount == 2)
    }
    
    func testKeychainPathValid() {
        let (keychainCopy, keychain) = getKeychainCopy()
        
        var pathLength: UInt32 = 0
        var pathBuffer = UnsafeMutablePointer<Int8>.allocate(capacity: 0)
        
        assert(SecKeychainGetPath(keychain, &pathLength, pathBuffer) == errSecBufferTooSmall)
        pathLength += 1
        pathBuffer = UnsafeMutablePointer<Int8>.allocate(capacity: Int(pathLength))
        assert(SecKeychainGetPath(keychain, &pathLength, pathBuffer) == kOSReturnSuccess)
        
        let path = String(cString: pathBuffer)
        
        assert(path.standardizePath() == keychainCopy.absoluteString.toUnixPath().standardizePath())
    }
    
    func testMapSetOwnerACL() {
        let (keychainCopy, keychain) = getKeychainCopy()
        let issuer = getCertificateIssuer(keychain: keychain)
        
        let configuration = modifyConfigurationForDemoKeychain(configuration: Configuration.read(path: testConfiguration), demoKeychainPath: keychainCopy, issuer: issuer)
        
        let syncronizer = Syncronizer(configuration: configuration)
        
        let results = syncronizer.mapIdentities()
        
        assert(results.count == 1)
        
        syncronizer.ensureSelfInOwnerACL(identity: (results.first?.identity)!)
    }

    func testExportItems() {
        let (keychainCopy, keychain) = getKeychainCopy()
        let issuer = getCertificateIssuer(keychain: keychain)
        
        let configuration = modifyConfigurationForDemoKeychain(configuration: Configuration.read(path: testConfiguration), demoKeychainPath: keychainCopy, issuer: issuer)
        
        let syncronizer = Syncronizer(configuration: configuration)
        
        let results = syncronizer.mapIdentities()
        
        assert(results.count == 1)
        
        syncronizer.exportKeychainItems(items: results)
        
        for item in configuration.existing {
            for export in item.exports {
                assert(FileManager.default.fileExists(atPath: export.path.absoluteString.toUnixPath()))
            }
        }
    }
    
    func testSetACLForApplications() {
        let (keychainCopy, keychain) = getKeychainCopy()
        let issuer = getCertificateIssuer(keychain: keychain)
        
        let configuration = modifyConfigurationForDemoKeychain(configuration: Configuration.read(path: testConfiguration), demoKeychainPath: keychainCopy, issuer: issuer)
        
        let syncronizer = Syncronizer(configuration: configuration)
        
        syncronizer.ensureACLContainsApps(aclName: configuration.aclName, items: syncronizer.mapIdentities())
    }
    
    func testSetupAllACLs() {
        let (keychainCopy, keychain) = getKeychainCopy()
        let issuer = getCertificateIssuer(keychain: keychain)
        
        let configuration = modifyConfigurationForDemoKeychain(configuration: Configuration.read(path: testConfiguration), demoKeychainPath: keychainCopy, issuer: issuer)
        
        let syncronizer = Syncronizer(configuration: configuration)
        let items = syncronizer.mapIdentities()
        
        for item in items {
            syncronizer.ensureSelfInOwnerACL(identity: item.identity)
        }
        syncronizer.ensureACLContainsApps(aclName: configuration.aclName, items: items)
    }
    
    func testSetupAllACLsIdempotent() {
        let (keychainCopy, keychain) = getKeychainCopy()
        let issuer = getCertificateIssuer(keychain: keychain)
        
        let configuration = modifyConfigurationForDemoKeychain(configuration: Configuration.read(path: testConfiguration), demoKeychainPath: keychainCopy, issuer: issuer)
        
        let syncronizer = Syncronizer(configuration: configuration)
        let items = syncronizer.mapIdentities()
        
        for item in items {
            syncronizer.ensureSelfInOwnerACL(identity: item.identity)
        }
        syncronizer.ensureACLContainsApps(aclName: configuration.aclName, items: items)
        
        for item in items {
            syncronizer.ensureSelfInOwnerACL(identity: item.identity)
        }
        syncronizer.ensureACLContainsApps(aclName: configuration.aclName, items: items)
    }
}
