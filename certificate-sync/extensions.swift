//
//  string_extensions.swift
//  certificate-sync
//
//  Created by Rick Mark on 11/22/18.
//  Copyright © 2018 Dropbox. All rights reserved.
//

import Foundation

extension String {
    func toUnixPath() -> String {
        if self.starts(with: "file:") {
            let fileUrl = URL(string: self)
            return fileUrl!.path
        }
        else {
            return self
        }
    }
    
    func toFileURL() -> URL {
        return URL(fileURLWithPath: self)
    }
}


extension IteratorProtocol {
    mutating func toDictionary<T, K : Hashable, V>(functor: (T) -> (key: K, value: V)) -> [ K: V ] {
        var result = [ K: V]()
        
        let element = self.next()
        
        while (element != nil) {
            let mapping = functor(element as! T)
            
            result.updateValue(mapping.1, forKey: mapping.0)
        }
        
        return result
    }
}
