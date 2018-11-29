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

    override func setUp() {
        let selfBundle = Bundle(for: type(of: self))
        testConfiguration = selfBundle.url(forResource: "test_configuration", withExtension: "plist")
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    private func getKeychainCopy() -> URL {
        let tempDirectoryURL = NSURL.fileURL(withPath: NSTemporaryDirectory(), isDirectory: true)
        
        let tempKeychainFile = tempDirectoryURL.appendingPathComponent("\(UUID().uuidString)-demo.keychain")

        var keychain: SecKeychain?
        let createResult = SecKeychainCreate(tempKeychainFile.absoluteString.toUnixPath(), 0, "", false, nil, &keychain)
        
        
        
        return tempKeychainFile
    }
    
    private func modifyConfigurationForDemoKeychain(configuration: Configuration, demoKeychainPath: URL) -> Configuration {
        let mapping = configuration.items.map { (item) -> ConfigurationItem in
            if item.keychainPath == "demo.keychain" {
                return ConfigurationItem(issuer: item.issuer, exports: item.exports, acls: item.acls, keychainPath: demoKeychainPath.absoluteString, password: item.password)
            }
            else {
                return item
            }
        }
        
        return Configuration(items: mapping)
    }

    func testLoadConfiguration() {
        let _ = Configuration.read(path: testConfiguration)
    }

    func testMapIdentities() {
        let keychainCopy = getKeychainCopy()
        
        let configuration = modifyConfigurationForDemoKeychain(configuration: Configuration.read(path: testConfiguration), demoKeychainPath: keychainCopy)
        
        let syncronizer = Syncronizer(configuration: configuration)
        
        let results = syncronizer.mapIdentities()
        
        assert(results.count == 1)
    }
    
    func testMapSetOwnerACL() {
        let keychainCopy = getKeychainCopy()
        
        let configuration = modifyConfigurationForDemoKeychain(configuration: Configuration.read(path: testConfiguration), demoKeychainPath: keychainCopy)
        
        let syncronizer = Syncronizer(configuration: configuration)
        
        let results = syncronizer.mapIdentities()
        
        assert(results.count == 1)
        
        syncronizer.ensureSelfInOwnerACL(identity: (results.first?.1)!)
    }

}
