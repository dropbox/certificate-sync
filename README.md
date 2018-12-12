# `certificate-sync` for macOS Keychain

macOS provides the Keychain as a way to store and retrieve credentials.
Unfortunately, there are many programs that may not be designed to use
the keychain.  This leads to problems keeping consistent identity.
`certificate-sync` was built to solve problems of device identity at Dropbox.
It can either import a certificate / private-key from disk and set the ACL,
or it can take an item in the keychain and export it to disk (while also
adjusting the ACL).

Combining this with SCEP profiles allows for certificates to be used by
other daemons on the box which are not keychain aware.


## LICENSE

This project is licensed under the Apache License, Version 2.0

## Contributing

Dropbox accepts contributions to open source projects.  Before submitting a
pull request, please have filed out a Dropbox Contributor License Agreement
form.

https://opensource.dropbox.com/cla/
