//
//  main.swift
//  certificate-sync
//
//  Created by Rick Mark on 11/14/18.
//  Copyright © 2018 Dropbox. All rights reserved.
//

import Foundation

let configurationPath = (CommandLine.arguments[1] as NSString).expandingTildeInPath

let configuration = Configuration.read(path: configurationPath.toFileURL())

let syncronizer = Syncronizer(configuration: configuration)

syncronizer.run()
