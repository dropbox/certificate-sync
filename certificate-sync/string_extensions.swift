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
