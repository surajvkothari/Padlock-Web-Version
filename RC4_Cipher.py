# RC4 Cipher Algorithm

"""
Padlock Encryption Software
Copyright 2019

Created by: Suraj Kothari
For A-level Computer Science
at Woodhouse College.
"""

import imageCrypt
import base64
import os
import time


def getHexedPlainText(plainText):
    """ Returns the plaintext in hex form and separates it into blocks of 16 into a list. """

    # Creates a list of each character from the plaintext
    plainText = list(plainText)

    # Converts each character, in the plaintext, to hex from the list
    hexedPlainTextList = [hex(ord(char))[2:] for char in plainText]
    
    return hexedPlainTextList


def KSA(key):
    """
    --- The Key Scheduling Algorithm ---
    Generates a list of integers from 0 to 255 which are then swapped around
    using the key to create a pseudorandom list of integers.
    """

    # Creates the list of integers from 0 to 255
    S = [ints for ints in range(256)]

    j = 0

    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256

        # Swaps the values stored at i and j in S
        S[i], S[j] = S[j], S[i]

    return S


def getKeyStream(key):
    """ Generates a key stream using the pass key and yields each byte of it """

    # Limits the maximum size of the key to 32 hex characters
    key = key[:32]

    # Gets the stream cipher
    S = KSA(key)

    # Initialises iteration counters
    i = 0
    j = 0

    # Keeps on yielding a hex value
    while True:
        # Increments the iteration counters
        i = (i + 1) % 256
        j = (j + S[i]) % 256

        # Swaps the values stored at i and j in S
        S[i], S[j] = S[j], S[i]

        # Gets a certain value from the stream cipher
        K = S[(S[i] + S[j]) % 256]

        # Converts the integer to hex
        yield hex(K)[2:].zfill(2)


def encryptMessage(plaintext, passKey):
    """Takes in a plaintext and passkey and returns the ciphertext"""

    hexedPlainTextList = getHexedPlainText(plainText=plaintext)

    cipherText = ""

    for char, S in zip(hexedPlainTextList, getKeyStream(passKey)):
        XOR = int(char, 16) ^ int(S, 16)

        cipherText += hex(XOR)[2:].zfill(2)

    return cipherText


def decryptMessage(ciphertext, passKey):
    """Takes in a ciphertext and passkey and returns the plaintext"""

    plainText = ""

    # Separates the ciphertext into hex bytes
    denaryC = [ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]

    for byte, S in zip(denaryC, getKeyStream(passKey)):
        # XORs the byte with the equivalent key stream hex value
        XOR = int(byte, 16) ^ int(S, 16)

        plainText += chr(XOR)

    return plainText


def encryptFile(filename, filepath, passKey):
    """ Encryption for files """

    full_filename = filepath + "/" + filename

    # Generates lines from the file
    def getLines():
        with open(full_filename) as f:
            for line in f:
                if line != "\n":
                    yield line.split("\n")[0]
                else:
                    yield "\n"

    # Generates encrypted data
    def getEncryptedData():
        # Gets file lines from generator
        for L in getLines():
            if L != "\n":
                E = encryptMessage(plaintext=L, passKey=passKey)
            else:
                E = "\n"

            yield E

    newFilename = "{}/{}_{}_ENC.txt".format(filepath, filename[:-4], 'RC4')

    # Writes each line of encrypted data
    with open(newFilename, 'w') as f2:
        for e in getEncryptedData():
            if e != "\n":
                f2.write(e + "\n")
            else:
                f2.write("\n")

    return newFilename


def encryptFileBase64(filename, filepath, passKey):
    """ Encrypts the contents of any file """

    full_filename = filepath + "/" + filename

    with open(full_filename, "rb") as f:
        test = f.read()

        """
        Converts the binary file contents to base64
        and then formats it into ASCII form.
        """

        encoded = base64.b64encode(test).decode("ascii")

    Encrypted = encryptMessage(plaintext=encoded, passKey=passKey)

    extension = os.path.splitext(filename)[1]
    eLength = len(extension)
    newFilename = "{}/{}_{}_Base64_ENC{}".format(filepath, filename[:-eLength], 'RC4', extension)

    # Converts the ASCII encryption into bytes form to write to new file
    Encrypted = bytes(Encrypted, 'utf-8')

    # Writes encrypted data to new file
    with open(newFilename, 'wb') as f2:
        f2.write(Encrypted)

    return newFilename


def decryptFile(filename, filepath, passKey):
    """ Decrypts the contents of a text file """

    full_filename = filepath + "/" + filename

    # Generates lines from the file
    def getLines():
        with open(full_filename) as f:
            for line in f:
                if line != "\n":
                    yield line.split("\n")[0]
                else:
                    yield "\n"

    # Generates decrypted data
    def getDecryptedData():
        # Gets file lines from generator
        for L in getLines():
            if L != "\n":
                D = decryptMessage(ciphertext=L, passKey=passKey)

            else:
                D = "\n"

            yield D

    if "ENC" in filename:
        newFilename = "{}/{}".format(filepath, filename.replace("ENC", "DEC"))
    else:
        newFilename = "{}/{}_{}_DEC.txt".format(filepath, filename[:-4], 'RC4')

    # Writes each line of encrypted data
    with open(newFilename, 'w') as f2:
        for d in getDecryptedData():
            if d != "\n":
                f2.write(d + "\n")
            else:
                f2.write("\n")

    return newFilename


def decryptFileBase64(filename, filepath, passKey):
    """ Decrypts the contents of any file """

    full_filename = filepath + "/" + filename

    with open(full_filename, "rb") as f:
        # Formats the binary file into ASCII form.
        content = f.read().decode("ascii")

    Decrypted = decryptMessage(ciphertext=content, passKey=passKey)

    if "ENC" in filename:
        newFilename = "{}/{}".format(filepath, filename.replace("ENC", "DEC"))
    else:
        extension = os.path.splitext(filename)[1]
        eLength = len(extension)
        newFilename = "{}/{}_{}_Base64_DEC{}".format(filepath, filename[:-eLength], 'RC4', extension)

    # Converts the ASCII into bytes and then decodes it from base64 to original
    decryptedContent = base64.b64decode(bytes(Decrypted, 'utf-8'))

    # Creates decrypted file
    with open(newFilename, 'wb') as f2:
        f2.write(decryptedContent)

    return newFilename


def encryptCheck(passKey, dataformat, cipherMode=None, plaintext=None, filename=None, filepath=None):
    """ Organises how the different dataformats are encrypted """

    if dataformat == "Messages":
        encryptedData = encryptMessage(plaintext=plaintext, passKey=passKey)
        timeTaken = 0

    elif dataformat == "Files":
        if cipherMode == "Base64":
            start = time.time()

            encryptedData = encryptFileBase64(filename=filename, passKey=passKey, filepath=filepath)

            end = time.time()
            timeTaken = end - start
        else:
            start = time.time()

            encryptedData = encryptFile(filename=filename, filepath=filepath, passKey=passKey)

            end = time.time()
            timeTaken = end - start

    elif dataformat == "Images":
        start = time.time()

        shift = KSA(key=passKey)
        encryptedData = imageCrypt.encrypt(filename=filename, filepath=filepath, shifts=shift, cipherUsed="RC4")

        end = time.time()
        timeTaken = end - start

    return encryptedData, timeTaken


def decryptCheck(passKey, dataformat, cipherMode=None, ciphertext=None, filename=None, filepath=None):
    """ Organises how the different dataformats are decrypted """

    if dataformat == "Messages":
        decryptedData = decryptMessage(ciphertext=ciphertext, passKey=passKey)
        timeTaken = 0

    elif dataformat == "Files":
        if cipherMode == "Base64":
            start = time.time()

            decryptedData = decryptFileBase64(filename=filename, passKey=passKey, filepath=filepath)

            end = time.time()
            timeTaken = end - start

        else:
            start = time.time()

            decryptedData = decryptFile(filename=filename, filepath=filepath, passKey=passKey)

            end = time.time()
            timeTaken = end - start

    elif dataformat == "Images":
        start = time.time()
        shift = KSA(key=passKey)

        decryptedData = imageCrypt.decrypt(filename=filename, filepath=filepath, shifts=shift, cipherUsed="RC4")

        end = time.time()
        timeTaken = end - start

    return decryptedData, timeTaken


def encrypt(passKey, dataformat, cipherMode=None, plaintext=None, filename=None, filepath=None):
    return encryptCheck(passKey, dataformat, cipherMode=cipherMode, plaintext=plaintext,
        filename=filename, filepath=filepath)


def decrypt(passKey, dataformat, cipherMode=None, ciphertext=None, filename=None, filepath=None):
    return decryptCheck(passKey, dataformat, cipherMode=cipherMode, ciphertext=ciphertext,
        filename=filename, filepath=filepath)
