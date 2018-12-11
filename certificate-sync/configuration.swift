//
//  configuration.swift
//  certificate-sync
//
//  Created by Rick Mark on 11/22/18.
//  Copyright © 2018 Dropbox. All rights reserved.
//

import Foundation

class Configuration {
    let aclName: String
    let existing: [ ConfigurationItem ]
    let imports: [ ImportItem ]
    
    init(aclName: String, existing : [ ConfigurationItem ], imports: [ ImportItem ]) {
        self.aclName = aclName
        self.existing = existing
        self.imports = imports
    }
    
    static func read(path: URL) -> Configuration {
        let configuration = NSDictionary.init(contentsOf: path)
        
        assert(configuration != nil)
        
        let items = configuration!.value(forKey: "existing") as? [ [ String : Any ] ] ?? []
        let aclName = configuration!.value(forKey: "acl_name") as? String ?? "com.dropbox.certificate-sync.acl"
        
        let existing = items.map({ (item) -> ConfigurationItem in
            return ConfigurationItem.parse(configuration: item)
        })
        
        let imports = (configuration!.value(forKey: "imports") as? [ [ String : Any ] ] ?? []).map { (item) -> ImportItem in
            return ImportItem.parse(configuration: item)
        }
        
        return Configuration(aclName: aclName, existing: existing, imports: imports)
    }
}
