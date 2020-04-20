# HIBPChecker
Simple and fast 100% offline password checker for Windows working with the password database available at https://haveibeenpwned.com/Passwords

Download the one with SHA1 hashes, ordered by hash.

Also useful as a simple example for how to memory map huge files on Windows, and calculate hash values using "Cryptography API: Next Generation" available in Windows.

No external dependencies apart from Windows SDK.

## Building

Build it with Visual Studio 2019 Community Edition, which can be downloaded here https://visualstudio.microsoft.com/downloads/

No prebuilt binary available, since you shouldn't input your password into binaries built by someone else. Of course you should also inspect the source code first.

## Usage
Currently only has a super simple command line interface:
```
HIBPChecker.exe [passwordDatabase.txt] passwordToCheck
```
