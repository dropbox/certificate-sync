//
//  export_configuration_item.swift
//  certificate-sync
//
//  Created by Rick Mark on 11/22/18.
//  Copyright © 2018 Dropbox. All rights reserved.
//

import Foundation

class ExportConfigurationItem {
    
    let format: SecExternalFormat
    let path: URL
    let owner: String?
    let mode: mode_t
    let pemEncode: Bool
    
    init(format: SecExternalFormat, path: URL, owner: String?, mode: mode_t, pemArmor: Bool) {
        self.format = format
        self.path = path
        self.owner = owner
        self.mode = mode
        self.pemEncode = pemArmor
    }
    
    static func parse(configuration: [ String : Any ]) -> ExportConfigurationItem {
        var format: SecExternalFormat
        var pemArmor = false
        switch configuration["format"] as! String {
        case "pem":
            format = SecExternalFormat.formatPEMSequence
        case "pem-cer":
            format = SecExternalFormat.formatX509Cert
            pemArmor = true
        default:
            format = SecExternalFormat.formatX509Cert
        }
        
        let mode = (configuration["mode"] ?? UInt16(600)) as! mode_t
        
        let owner = configuration["owner"] as? String
        
        let path = (configuration["path"] as! String).toFileURL()
        
        return ExportConfigurationItem(format: format, path: path, owner: owner, mode: mode, pemArmor: pemArmor)
    }
}
