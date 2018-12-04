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
    let tag = "com.dropbox.entsec.certificate-sync.tests".data(using: .utf8)!

    override func setUp() {
        let selfBundle = Bundle(for: type(of: self))
        testConfiguration = selfBundle.url(forResource: "test_configuration", withExtension: "plist")
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    private func getKeychainCopy() -> (URL, SecKeychain) {
        let tempDirectoryURL = NSURL.fileURL(withPath: NSTemporaryDirectory(), isDirectory: true)
        
        let tempKeychainFile = tempDirectoryURL.appendingPathComponent("\(UUID().uuidString)-demo.keychain")

        var keychain: SecKeychain?
        assert(SecKeychainCreate(tempKeychainFile.absoluteString.toUnixPath(), 0, "", false, nil, &keychain) == kOSReturnSuccess)
        
        var privateKey: SecKey!
        var publicKey: SecKey!
        
        let generationAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 4096,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag
            ]
        ]
        
        assert(SecKeyGeneratePair(generationAttributes as CFDictionary, &publicKey, &privateKey) == kOSReturnSuccess)
        
        let storePublicKey: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: "\(tag).public",
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
        let tempDirectoryURL = NSURL.fileURL(withPath: NSTemporaryDirectory(), isDirectory: true)
        
        let mapping = configuration.items.map { (item) -> ConfigurationItem in
            if item.keychainPath == "demo.keychain" {
                
                let exports = item.exports.map({ (export) -> ExportConfigurationItem in
                    let newPath = tempDirectoryURL.appendingPathComponent(export.path.absoluteString)
                    
                    return ExportConfigurationItem(format: export.format, path: newPath, owner: export.owner, mode: export.mode, pemArmor: export.pemEncode)
                })
                
                return ConfigurationItem(issuer: issuer, exports: exports, acls: item.acls, keychainPath: demoKeychainPath.absoluteString, password: item.password)
            }
            else {
                return item
            }
        }
        
        return Configuration(items: mapping)
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

    func testMapIdentities() {
        let (keychainCopy, keychain) = getKeychainCopy()
        
        let issuer = getCertificateIssuer(keychain: keychain)
        let configuration = modifyConfigurationForDemoKeychain(configuration: Configuration.read(path: testConfiguration), demoKeychainPath: keychainCopy, issuer: issuer)
        
        let syncronizer = Syncronizer(configuration: configuration)
        
        let results = syncronizer.mapIdentities()
        
        assert(results.count == 1)
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
        
        syncronizer.ensureSelfInOwnerACL(identity: (results.first?.1)!)
    }

    func testExportItems() {
        let (keychainCopy, keychain) = getKeychainCopy()
        let issuer = getCertificateIssuer(keychain: keychain)
        
        let configuration = modifyConfigurationForDemoKeychain(configuration: Configuration.read(path: testConfiguration), demoKeychainPath: keychainCopy, issuer: issuer)
        
        let syncronizer = Syncronizer(configuration: configuration)
        
        let results = syncronizer.mapIdentities()
        
        assert(results.count == 1)
        
        syncronizer.exportKeychainItems(items: results)
    }
}
