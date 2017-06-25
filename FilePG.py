#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File Privacy Guard (FPG) v0.1

FPG can be used to batch encrypt and split files
Encryption is provided by GnuPG

Requires Python 3.6+ for secrets library

Repo: https://github.com/TonyWu386/File-Privacy-Guard

This software is licensed under the GNU GPL v3.0
"""

from subprocess import run, PIPE
from os import listdir, statvfs
from os.path import isfile, join
from secrets import choice
from time import time
from sys import platform

import string

# Config parameters
# -------------------------------
CIPHER = "AES256"
DIGEST = "SHA256"
DETECTEDFILETYPES = ["zip", "7z"]    
# passphrases of this length will be used
KEYLENGTH = 20
# file larger than this size in MB will be split
SPLITLIMIT = 1000
# this extension will be appended to the end of files
EXT = ".enc"
# compression level, "0" recommended for best performance
COMP = "0"


class FileObj():
    # represents a file to be processed by FPG

    def __init__(self, fileName):
        '''(str) -> FileObj
        Initializes a FileObj with a file name
        '''

        self._fileName = fileName
        retVal = run(["stat", "--printf=\"%s\"", fileName], stdout=PIPE)
        retVal.check_returncode()
        self._fileSize = int(retVal.stdout.decode("utf-8")[1:-1]) / 1048576
        self._key = None
        self._isEncrypted = False


    def encrypt(self):
        '''() -> None
        Encrypts the file represented by the object instance
        '''

        alphabet = string.ascii_letters + string.digits
        password = ''.join(choice(alphabet) for i in range(KEYLENGTH))
        self._key = password

        retVal = run(["gpg", "--batch", "--passphrase", password,
                "--digest-algo", DIGEST, "--symmetric",
                "--cipher-algo", CIPHER, "--compress-level", COMP,
                "--output", self._fileName + EXT, self._fileName])

        retVal.check_returncode()
        self._isEncrypted = True


    def splitIfShouldSplit(self):
        '''() -> int
        If the file is larger than SPLITLIMIT, split the file
        Returns 0 if file was actually split, else 1
        '''

        if not self._isEncrypted:
            raise Exception('File has not been encrypted yet')

        if self._fileSize > SPLITLIMIT:
            retVal = run(["split", "--bytes=" + str(SPLITLIMIT) + "M",
                          "--numeric-suffixes", "--suffix-length=2",
                          self._fileName + EXT, self._fileName + EXT + "."])
            retVal.check_returncode()
            retVal = run(["rm", self._fileName + EXT])
            retVal.check_returncode()
            return 0
        else:
            return 1


    def rename(self, newName):
        '''() -> None
        Renames the file represented by the object instance
        '''

        retVal = run(["mv", self._fileName + EXT, newName + EXT])
        retVal.check_returncode()
        self._fileName = newName


    def getSize(self):
        '''() -> float
        Gets the rounded file size
        '''

        return round(self._fileSize, 2)


    def getKey(self):
        '''() -> str
        Returns the key used to encrypt this file
        '''

        if not self._isEncrypted:
            raise Exception('File has not been encrypted yet')

        return self._key


    def getEncryptionSpeed(self, deltaTime):
        '''(float) -> float
        Gets the rounded encryption speed give the time delta
        '''

        return round(self._fileSize / deltaTime, 2)


    def isEncrypted(self):
        '''() -> bool
        Returns True if the file has been encrypted
        '''

        return self._isEncrypted


    def __str__(self):
        return str(self._fileName)



def keyPrinter(fileObjList):
    '''(List) -> None
    Prints out the encryption passphrases from a list of FileObj
    '''

    for fileObj in fileObjList:
        if fileObj.isEncrypted():
            print(str(fileObj) + " : " + fileObj.getKey() + "\n")


def totalFileSize(fileObjList):
    '''(List) -> float
    Returns the combined total file size form a list of FileObj
    '''

    totalSize = 0.0
    for fileObj in fileObjList:
        totalSize += fileObj.getSize()

    return totalSize


def platformValidation():
    '''() -> int
    Return 0 if platform is supported, else a status code
    '''

    status = 0

    if (platform != 'linux'):
        status = 1
    retVal = run(["gpg", "--version"], stdout=PIPE)
    try:
        retVal.check_returncode()
    except:
        status = 2
    gpgVersion = retVal.stdout.decode("utf-8")
    if (gpgVersion[0:14] != "gpg (GnuPG) 2."):
        status = 3
    if KEYLENGTH < 10:
        status = 4
    if (CIPHER not in gpgVersion):
        status = 5
    if (DIGEST not in gpgVersion):
        status = 6
    if (len(EXT) < 1):
        status = 7

    return status


if __name__ == "__main__":

    platformStatus = platformValidation()

    if platformStatus != 0:
        if platformStatus == 1:
            print("Tool should be ran on Linux. Exiting.")
        elif platformStatus == 2:
            print("GnuPG cannot be called. Exiting.")
        elif platformStatus == 3:
            print("GPG version 2.+ recommended")
        elif platformStatus == 4:
            print("Key length should be longer")
        elif platformStatus == 5:
            print("Cipher not supported")
        elif platformStatus == 6:
            print("Digest not supported")
        else:
            print("Extension length too short")
        quit()

    else:
        print("Platform and config validated\n")

    fileNameList = [fi for fi in listdir("./") if (isfile(join("./", fi)) \
                                  and fi[-3:] in DETECTEDFILETYPES)]

    # Create the fileObj instances
    fileObjList = []
    for fileName in fileNameList:
        fileObjList.append(FileObj(fileName))

    # some additional verification
    if (len(fileObjList) == 0):
        print("No supported files detected. Exiting.")
        quit()

    statResult = statvfs("./")
    freeSpace = round((statResult.f_bsize * statResult.f_bavail) / 1048576, 2)
    totalFileSize = totalFileSize(fileObjList)

    print("Free space: " + str(freeSpace) + " MB\n")
    print("Total file size " + str(totalFileSize))
    if freeSpace < totalFileSize:
        print("Are you sure there is enough space?")

    print(str(len(fileObjList)) + " files detected:\n")
    for fileObj in fileObjList:
        print(str(fileObj) + " - " + str(fileObj.getSize()) + "MB\n")
    print("...........................................")
    print(CIPHER, DIGEST, str(KEYLENGTH) + "-char-passphrases",
          str(SPLITLIMIT) + "-MB-splitting", EXT + "-extension",
          COMP + "-compression\n")

    userIn = input("Enter 'y' to begin encryption with above parameters\n")

    if userIn != 'y':
        quit()

    overallStart = time()

    # encryption
    for fileObj in fileObjList:

        print("Working on " + str(fileObj) + ", " + str(fileObj.getSize()) + \
              " MB")

        start = time()

        try:
            fileObj.encrypt()
        except:
            print("GPG error during encryption of " + str(fileObj) + "!")
            while True:
                userIn = input("Enter 'v' to view keys, 'q' to quit");
                if userIn == 'q':
                    quit()
                if userIn == 'v':
                    keyPrinter(fileObjList)
                    quit()

        deltaTime = time() - start
        print(str(fileObj) + " encrypted in " + str(round(deltaTime, 2)) + \
              " sec\n")
        print("Average speed: " + str(fileObj.getEncryptionSpeed(deltaTime)) \
              + " MB/s\n")

    print ("All files encrypted in " + str(time() - overallStart) + "s\n")

    while userIn != 'v':
        userIn = input("Enter 'v' to view passphrases\n")

    keyPrinter(fileObjList)   
    print("This is your only chance to record these!")

    userIn = input("Enter 'r' for renaming, other key to skip")

    # renaming
    if userIn == 'r':
        for fileObj in fileObjList:
            print("For file: " + str(fileObj))
            userIn = input("Enter new name: ")
            fileObj.rename(userIn)
            print("Renamed\n")

    # splitting
    print("Splitting files if needed...")
    for fileObj in fileObjList:
        if (fileObj.splitIfShouldSplit() == 0):
            print(str(fileObj) + " was split")
        else:
            print(str(fileObj) + " was not split")