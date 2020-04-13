# HIBPChecker
Simple and fast 100% offline password checker for Windows working with the password database available at https://haveibeenpwned.com/Passwords

Download the one with SHA1 hashes, ordered by hash.

Also useful as a simple example for how to memory map huge files on Windows, and calculate hash values using "Cryptography API: Next Generation" available in Windows.

No external dependencies apart from Windows SDK.

## Usage
Currently only has a super simple command line interface:
```
HIBPChecker.exe [passwordDatabase.txt] passwordToCheck
```
