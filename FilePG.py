#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File Privacy Guard (FPG) v0.2

FPG can be used to batch encrypt and split files
FPG generates passphrases for each file, and can automatically rename them
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
from string import digits, ascii_letters

# Config parameters
# -------------------------------
CIPHER = "AES256"
DIGEST = "SHA256"
DETECTEDFILETYPES = ["bmp", "7z"]    
# passphrases of this length will be used
PASSLENGTH = 20
# file larger than this size in MB will be split
SPLITLIMIT = 1
# this extension will be appended to the end of files
EXT = ".enc"
# compression level, "0" recommended for best performance
COMP = "0"

# if random rename is used, the length of the random name
RENAMELEN = 4
# if random rename is used. this fixed prefix will be added to every file name
NAMEPREFIX = "B"


class GuardObj():
    # represents a file to be processed by FPG

    def __init__(self, fileName):
        '''(str) -> GuardObj
        Initializes a GuardObj with a file name
        '''

        self._fileName = fileName
        self._extension = fileName[fileName.rfind(".") + 1:]
        retVal = run(["stat", "--printf=\"%s\"", fileName], stdout=PIPE)
        retVal.check_returncode()
        self._fileSize = int(retVal.stdout.decode("utf-8")[1:-1]) / 1048576
        self._key = None
        self._isEncrypted = False


    def encrypt(self):
        '''() -> None
        Encrypts the file represented by the object instance
        '''

        alphabet = ascii_letters + digits
        password = ''.join(choice(alphabet) for i in range(PASSLENGTH))
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
        Returns the number of pieces the file was split into
        '''

        if not self._isEncrypted:
            raise Exception('File has not been encrypted yet')

        if self._fileSize > SPLITLIMIT:
            retVal = run(["split", "--bytes=" + str(SPLITLIMIT) + "M",
                          "--numeric-suffixes", "--suffix-length=2",
                          "--verbose", self._fileName + EXT, self._fileName \
                          + EXT + "."], stdout=PIPE)
            retVal.check_returncode()
            pieces = len(retVal.stdout.decode("utf-8").split("\n")) - 1
            retVal = run(["rm", self._fileName + EXT])
            retVal.check_returncode()
            return pieces
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


    def getExtension(self):
        '''() -> str
        Returns the extension of the file
        '''

        return self._extension


    def __str__(self):
        fileNameLength = len(self._fileName)

        if (fileNameLength < 25):
            displayName = self._fileName
        else:
            displayName = self._fileName[:10] + "..." + \
            self._fileName[fileNameLength - 10 :]

        return str(displayName)



def keyPrinter(guardObjList):
    '''(List) -> None
    Prints out the encryption passphrases from a list of GuardObj
    '''

    for guardObj in guardObjList:
        if guardObj.isEncrypted():
            print(str(guardObj) + " : " + guardObj.getKey() + "\n")


def totalFileSize(guardObjList):
    '''(List) -> float
    Returns the combined total file size form a list of GuardObj
    '''

    totalSize = 0.0
    for guardObj in guardObjList:
        totalSize += guardObj.getSize()

    return totalSize


def platformValidation():
    '''() -> int
    Return 0 if platform is supported, else an integer status code
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
    if PASSLENGTH < 10:
        status = 4
    if (CIPHER not in ("IDEA", "3DES", "CAST5", "BLOWFISH", "AES", "AES192",
        "AES256", "TWOFISH", "CAMELLIA128", "CAMELLIA192", "CAMELLIA256")):
        status = 5
    if (DIGEST not in ("SHA1", "RIPEMD160", "SHA256", "SHA384", "SHA512",
                       "SHA224")):
        status = 6
    if (len(EXT) < 1):
        status = 7

    return status


if __name__ == "__main__":

    platformStatus = platformValidation()

    if (platformStatus != 0):
        if (platformStatus == 1):
            print("Tool should be ran on Linux. Exiting.")
        elif (platformStatus == 2):
            print("GnuPG cannot be called. Exiting.")
        elif (platformStatus == 3):
            print("GPG version 2.+ recommended")
        elif (platformStatus == 4):
            print("Passphrase length should be longer")
        elif (platformStatus == 5):
            print("Cipher " + CIPHER + " not supported")
        elif (platformStatus == 6):
            print("Digest " + DIGEST + "not supported")
        else:
            print("Extension length too short")
        quit()

    else:
        print("Platform and config validated\n")
    
    print("Using " + CIPHER + ", " + DIGEST + " with " + str(PASSLENGTH) + \
          " character passphrases. Splitting at " + str(SPLITLIMIT) + \
          "MB. " + EXT + " extensions." + COMP + " compression\n")

    fileNameList = [fi for fi in listdir("./") if (isfile(join("./", fi)) \
                                  and fi[-3:] in DETECTEDFILETYPES)]

    # Create the guardObj instances
    guardObjList = []
    for fileName in fileNameList:
        guardObjList.append(GuardObj(fileName))

    # some additional verification
    if (len(guardObjList) == 0):
        print("No supported files detected. Exiting.")
        quit()

    statResult = statvfs("./")
    freeSpace = round((statResult.f_bsize * statResult.f_bavail) / 1048576, 2)
    totalFileSize = totalFileSize(guardObjList)

    print("Free space: " + str(freeSpace) + " MB\n")
    print("Total file size " + str(totalFileSize) + " MB\n")
    if (freeSpace < totalFileSize):
        print("Are you sure there is enough space?")

    print(str(len(guardObjList)) + " files detected:\n")
    for guardObj in guardObjList:
        print(str(guardObj) + " - " + str(guardObj.getSize()) + "MB\n")
    print("...........................................")

    userIn = input("Enter 'y' to begin encryption with above parameters\n")

    if (userIn != 'y'):
        quit()

    overallStart = time()

    # encryption
    for guardObj in guardObjList:

        print("Working on " + str(guardObj) + ", " + \
              str(guardObj.getSize()) + " MB")

        start = time()

        try:
            guardObj.encrypt()
        except:
            print("GPG error during encryption of " + str(guardObj) + "!")
            while True:
                userIn = input("Enter 'v' to view keys, 'q' to quit");
                if userIn == 'q':
                    quit()
                if userIn == 'v':
                    keyPrinter(guardObjList)
                    quit()

        deltaTime = time() - start
        print(str(guardObj) + " encrypted in " + str(round(deltaTime, 2)) + \
              " sec\n")
        print("Average speed: " + str(guardObj.getEncryptionSpeed(deltaTime)) \
              + " MB/s\n")

    print ("All files encrypted in " + str(time() - overallStart) + "s\n")

    while userIn != 'v':
        userIn = input("Enter 'v' to view passphrases\n")

    keyPrinter(guardObjList)   
    print("This is your only chance to record these!")

    userIn = input("Enter 'r' for renaming, 'a' for random renaming, " +
                   "other key to skip\n")

    # renaming
    if (userIn == 'r' or userIn == 'a'):
        for guardObj in guardObjList:
            print("For file: " + str(guardObj))
            if (userIn == 'r'):
                newName = input("Enter new name: ")
            else:
                # automated renaming
                newName = NAMEPREFIX
                newName += ''.join(choice(digits) for i in range(RENAMELEN))
                newName += "." + guardObj.getExtension()
                print("Automatically renamed " + newName + " to " + \
                      str(guardObj))
            guardObj.rename(newName)

    # splitting
    print("Splitting files if needed")
    for guardObj in guardObjList:
        pieces = guardObj.splitIfShouldSplit()
        if (pieces == 1):
            print(str(guardObj) + " was not split")
        else:
            print(str(guardObj) + " was split into " + str(pieces) + " pieces")
