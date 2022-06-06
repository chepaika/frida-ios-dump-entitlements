# frida-ios-dump-entitlements

Tool for dump entitlements from binary on ios. Currently configured for dumping only keychain access groups, but you can modify it esealy.

Tool based on [@AloneMonkey](https://github.com/AloneMonkey) [frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump)

## Usage 

 1. Install [frida](http://www.frida.re/) on device
 2. `sudo pip install -r requirements.txt --upgrade`
 4. Run python3 read_entitlements.py `Display name` or `Bundle identifier`