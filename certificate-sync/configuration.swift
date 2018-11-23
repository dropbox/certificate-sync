//
//  configuration.swift
//  certificate-sync
//
//  Created by Rick Mark on 11/22/18.
//  Copyright © 2018 Dropbox. All rights reserved.
//

import Foundation

class Configuration {
    let items: [ ConfigurationItem ]
    
    init(items : [ ConfigurationItem ]) {
        self.items = items
    }
    
    static func read(path: URL) -> Configuration {
        let configuration = NSDictionary.init(contentsOf: path)
        
        assert(configuration != nil)
        
        let items = configuration!.value(forKey: "items") as! [ [ String : Any ] ]
        
        return Configuration(items: items.map({ (item) -> ConfigurationItem in
            return ConfigurationItem.parse(configuration: item)
        }))
    }
}
