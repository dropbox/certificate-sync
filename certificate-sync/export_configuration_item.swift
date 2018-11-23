//
//  export_configuration_item.swift
//  certificate-sync
//
//  Created by Rick Mark on 11/22/18.
//  Copyright © 2018 Dropbox. All rights reserved.
//

import Foundation

class ExportConfigurationItem {
    enum Format {
        case PEM
        case CER
    }
    
    let format: Format
    let path: URL
    let owner: String
    let mode: mode_t
    
    init(format: Format, path: URL, owner: String, mode: mode_t) {
        self.format = format
        self.path = path
        self.owner = owner
        self.mode = mode
    }
    
    static func parse(configuration: [ String : Any ]) -> ExportConfigurationItem {
        var format: Format
        switch configuration["format"] as! String {
        case "pem":
            format = Format.PEM
        case "cer":
            format = Format.CER
        default:
            format = Format.CER
        }
        
        let mode = (configuration["mode"] ?? 600) as! mode_t
        
        let owner = configuration["owner"] as! String
        
        let path = (configuration["path"] as! String).toFileURL()
        
        return ExportConfigurationItem(format: format, path: path, owner: owner, mode: mode)
    }
}
