# Flokibot

## PayloadDump.py

PayloadDump takes a Flokibot sample like 7bd22e3147122eb4438f02356e8927f36866efa0cc07cc604f1bff03d76222a6, and extracts payload binaries from the compressed/encrypted PE resources. It outputs a file named BOT32 or BOT64 in the current working directory.

```
python PayloadDump.py samples\7bd22e3147122eb4438f02356e8927f36866efa0cc07cc604f1bff03d76222a6 BOT32
Successfully Dumped payload BOT32
```

## ConfigDump.py

ConfigDump takes a 32 bit Flokibot payload extracted using PayloadDump, and extracts the obfuscated config block containing a C2 URL and an RC4 network key. It outputs a file named config.bin, and prints out the URL contained in the deobfuscated config block.

```
python ConfigDump.py BOT32
Successfully dumped config.bin.
URL: https://adultgirlmail[.]com/mail/gate[.]php
```

## Required Python Libraries
* pefile
* rc4

```
pip install pefile rc4
```
