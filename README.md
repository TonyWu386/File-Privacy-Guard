# File-Privacy-Guard

Copyright (c) 2016 [Tony Wu], All Right Reserved

This software is licensed under the GNU GPL v3.0

Version 0.2

File Privacy Guard can be used to protect files for backup. It's recommended to create archives before feeding them to this tool. A random passphrase will be automatically generated for each file using Python3.6's secrets module. The files will then be encrypted and split to account for any maximum file size constraint. Automated renaming is also possible. Parameters such recongized files, passphrase strength, split size, and renaming can all be configured.

Dependencies:

Linux

GnuPG 2.x

Python3.6 (required for secrets module)

To use: run FilePG.py with Python3.6
