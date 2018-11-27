//
//  main.swift
//  certificate-sync
//
//  Created by Rick Mark on 11/14/18.
//  Copyright © 2018 Dropbox. All rights reserved.
//

import Foundation

let configurationPath = "/Users/rickmark/Developer/certificate-sync/certificate-sync/certificate-sync/configuration.plist"

let configuration = Configuration.read(path: configurationPath.toFileURL())

let syncronizer = Syncronizer(configuration: configuration)

syncronizer.run()

//for identityItem in (items! as! [[String: Any]]) {
//    if identityItem[kSecAttrIssuer as String] as? NSData != arubaIssuer {
//        continue
//    }
//
//    let identity = identityItem[kSecValueRef as String] as! SecIdentity
//    var privateKey: SecKey?
//    let key = Unmanaged.passRetained("some key" as CFTypeRef)
//
//    SecIdentityCopyPrivateKey(identity, &privateKey)
//
//    var exportParameters = SecItemImportExportKeyParameters()
//    exportParameters.passphrase = key
//
//
//    var outputData: CFData?
//
//    let exportResult = SecItemExport(privateKey!, .formatPKCS12, [], &exportParameters, &outputData)
//
//    print(exportResult)
//
//    print(outputData! as Data)
//}
