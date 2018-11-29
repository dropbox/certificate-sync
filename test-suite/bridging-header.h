//
//  bridging-header.h
//  certificate-sync
//
//  Created by Rick Mark on 11/29/18.
//  Copyright © 2018 Dropbox. All rights reserved.
//

#ifndef bridging_header_h
#define bridging_header_h

#define OPENSSL_TOO_OLD

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#endif /* bridging_header_h */
