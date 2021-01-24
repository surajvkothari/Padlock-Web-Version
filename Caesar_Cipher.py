# Caesar Cipher Algorithm

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


def getShiftKeyForImage(passKey):
    """ Returns a shift key value from the pass key for image cipher """
    ASCII_sum = 0

    for chr in passKey:
        ASCII_sum += ord(chr)

    return ASCII_sum


def getShiftKey_CLASSIC(passKey):
    """ Returns a shift key value from the pass key using the English Alphabet """

    Letter_sum = 0

    alphabet = "abcdefghijklmnopqrstuvwxyz"

    for chr in passKey:
        if chr.isalpha():  # Only alphabetical characters are used in the total
            Letter_sum += alphabet.index(chr.lower()) + 1


    return Letter_sum


def getShiftKey_ASCII(passKey):
    """ Returns a shift key value from the pass key using ASCII """

    ASCII_sum = 0

    for chr in passKey:
        ASCII_sum += ord(chr)

    return ASCII_sum


def encryptMessage_CLASSIC(plaintext, passKey):
    """ Encrypts a plaintext with a passkey in CLASSIC mode """

    cipherText = ""

    shift = getShiftKey_CLASSIC(passKey)

    alphabet = "abcdefghijklmnopqrstuvwxyz"

    for i, Letter in enumerate(plaintext):
        if Letter.isalpha():
            if Letter.isupper():
                letter_pos = alphabet.index(Letter.lower()) + 1

                # Gets the new position of the encrypted letter in the alphabet
                shiftedValue = (((letter_pos - 1) + shift) % 26) + 1

                # Gets the character at the new position.
                newLetter = alphabet[shiftedValue - 1]

                # Concatenates the encrypted character in uppercase onto the ciphertext
                cipherText += newLetter.upper()
            else:
                letter_pos = alphabet.index(Letter.lower()) + 1

                # Gets the new position of the encrypted letter in the alphabet
                shiftedValue = (((letter_pos - 1) + shift) % 26) + 1

                # Gets the letter at the new position.
                newLetter = alphabet[shiftedValue - 1]

                # Concatenates the encrypted character in uppercase onto the ciphertext
                cipherText += newLetter
        else:
            # Any non-alphabetical character is just added
            cipherText += Letter

    return cipherText


def encryptMessage_ASCII(plaintext, passKey):
    """ Encrypts a plaintext with a passkey in ASCII mode """

    cipherText = ""

    shift = getShiftKey_ASCII(passKey)

    for i, CHR in enumerate(plaintext):
        characterASCII = ord(CHR)

        # Gets the new position of the encrypted character in ASCII
        shiftedValue = (((characterASCII - 32) + shift) % 95) + 32

        # Gets the character at the new position.
        newChar = chr(shiftedValue)

        # Concatenates the encrypted character onto the ciphertext
        cipherText += newChar

    return cipherText


def decryptMessage_CLASSIC(ciphertext, passKey):
    """ Encrypts a plaintext with a passkey in CLASSIC mode """

    plainText = ""

    shift = getShiftKey_CLASSIC(passKey)

    alphabet = "abcdefghijklmnopqrstuvwxyz"

    for i, Letter in enumerate(ciphertext):
        if Letter.isalpha():
            if Letter.isupper():
                letter_pos = alphabet.index(Letter.lower()) + 1

                # Gets the new position of the encrypted letter in the alphabet
                shiftedValue = (((letter_pos - 1) - shift) % 26) + 1

                # Gets the character at the new position.
                newLetter = alphabet[shiftedValue - 1]

                # Concatenates the encrypted character in uppercase onto the ciphertext
                plainText += newLetter.upper()
            else:
                letter_pos = alphabet.index(Letter) + 1

                # Gets the new position of the encrypted letter in the alphabet
                shiftedValue = (((letter_pos - 1) - shift) % 26) + 1

                # Gets the letter at the new position.
                newLetter = alphabet[shiftedValue - 1]

                # Concatenates the encrypted character in uppercase onto the ciphertext
                plainText += newLetter
        else:
            # Any non-alphabetical character is just added
            plainText += Letter

    return plainText


def decryptMessage_ASCII(ciphertext, passKey):
    """ Decrypts a ciphertext with a passkey in ASCII mode """

    plainText = ""

    shift = getShiftKey_ASCII(passKey)

    for i, CHR in enumerate(ciphertext):
        characterASCII = ord(CHR)

        # Gets the new position of the decrypted character in ASCII
        shiftedValue = (((characterASCII - 32) - shift) % 95) + 32

        # Gets the character at the new position.
        newChar = chr(shiftedValue)

        # Concatenates the decrypted character onto the plaintext
        plainText += newChar

    return plainText


def encryptFile(filename, filepath, passKey, cipherMode):
    """ Encrypts the contents of a text file """

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
                if cipherMode == "ASCII":
                    E = encryptMessage_ASCII(plaintext=L, passKey=passKey)
                else:
                    E = encryptMessage_CLASSIC(plaintext=L, passKey=passKey)
            else:
                E = "\n"

            yield E

    newFilename = "{}/{}_{}_ENC.txt".format(filepath, filename[:-4], 'caesar')

    # Writes each line of encrypted data
    with open(newFilename, 'w') as f2:
        for e in getEncryptedData():
            if e != "\n":
                f2.write(e + "\n")
            else:
                f2.write("\n")

    return newFilename


def encryptFileBase64(filename, filepath, passKey):
    """ Encrypts the contents of any file using base64 """

    full_filename = filepath + "/" + filename

    with open(full_filename, "rb") as f:
        test = f.read()

        """
        Converts the binary file contents to base64
        and then formats it into ASCII form.
        """

        encoded = base64.b64encode(test).decode("ascii")

    Encrypted = encryptMessage_ASCII(plaintext=encoded, passKey=passKey)

    extension = os.path.splitext(filename)[1]
    eLength = len(extension)
    newFilename = "{}/{}_{}_Base64_ENC{}".format(filepath, filename[:-eLength], 'caesar', extension)

    # Converts the ASCII encryption into bytes form to write to new file
    Encrypted = bytes(Encrypted, 'utf-8')

    # Writes encrypted data to new file
    with open(newFilename, 'wb') as f2:
        f2.write(Encrypted)

    return newFilename


def decryptFile(filename, filepath, passKey, cipherMode):
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
                if cipherMode == "ASCII":
                    D = decryptMessage_ASCII(ciphertext=L, passKey=passKey)
                else:
                    D = decryptMessage_CLASSIC(ciphertext=L, passKey=passKey)
            else:
                D = "\n"

            yield D

    if "ENC" in filename:
        newFilename = "{}/{}".format(filepath, filename.replace("ENC", "DEC"))
    else:
        newFilename = "{}/{}_{}_DEC.txt".format(filepath, filename[:-4], 'caesar')

    # Writes each line of encrypted data
    with open(newFilename, 'w') as f2:
        for d in getDecryptedData():
            if d != "\n":
                f2.write(d + "\n")
            else:
                f2.write("\n")

    return newFilename


def decryptFileBase64(filename, filepath, passKey):
    """ Decrypts the contents of any file using base64 """

    full_filename = filepath + "/" + filename

    with open(full_filename, "rb") as f:
        # Formats the binary file into ASCII form.
        content = f.read().decode("ascii")

    Decrypted = decryptMessage_ASCII(ciphertext=content, passKey=passKey)

    if "ENC" in filename:
        newFilename = "{}/{}".format(filepath, filename.replace("ENC", "DEC"))
    else:
        extension = os.path.splitext(filename)[1]
        eLength = len(extension)
        newFilename = "{}/{}_{}_Base64_DEC{}".format(filepath, filename[:-eLength], 'caesar', extension)

    # Converts the ASCII into bytes and then decodes it from base64 to original
    decryptedContent = base64.b64decode(bytes(Decrypted, 'utf-8'))

    # Creates decrypted file
    with open(newFilename, 'wb') as f2:
        f2.write(decryptedContent)

    return newFilename


def encryptCheck(passKey, dataformat, cipherMode, plaintext=None, filename=None, filepath=None):
    """ Organises how the different dataformats are encrypted """
    if dataformat == "Messages":
        if cipherMode == "ASCII":
            encryptedData = encryptMessage_ASCII(plaintext=plaintext, passKey=passKey)
        else:
            encryptedData = encryptMessage_CLASSIC(plaintext=plaintext, passKey=passKey)

        timeTaken = 0

    elif dataformat == "Files":
        if cipherMode == "Base64":
            start = time.time()

            encryptedData = encryptFileBase64(filename=filename, filepath=filepath, passKey=passKey)

            end = time.time()
            timeTaken = end - start
        else:
            start = time.time()

            encryptedData = encryptFile(filename=filename, filepath=filepath, passKey=passKey, cipherMode=cipherMode)

            end = time.time()
            timeTaken = end - start

    elif dataformat == "Images":
        start = time.time()

        shift = getShiftKeyForImage(passKey=passKey)
        encryptedData = imageCrypt.encrypt(filename=filename, filepath=filepath, shifts=[shift], cipherUsed="caesar")

        end = time.time()
        timeTaken = end - start

    return encryptedData, timeTaken


def decryptCheck(passKey, dataformat, cipherMode, ciphertext=None, filename=None, filepath=None):
    """ Organises how the different dataformats are decrypted """
    if dataformat == "Messages":
        if cipherMode == "ASCII":
            decryptedData = decryptMessage_ASCII(ciphertext=ciphertext, passKey=passKey)
        else:
            decryptedData = decryptMessage_CLASSIC(ciphertext=ciphertext, passKey=passKey)

        timeTaken = 0

    elif dataformat == "Files":
        if cipherMode == "Base64":
            start = time.time()

            decryptedData = decryptFileBase64(filename=filename, filepath=filepath, passKey=passKey)

            end = time.time()
            timeTaken = end - start
        else:
            start = time.time()

            decryptedData = decryptFile(filename=filename, filepath=filepath, passKey=passKey, cipherMode=cipherMode)

            end = time.time()
            timeTaken = end - start

    elif dataformat == "Images":
        start = time.time()

        shift = getShiftKeyForImage(passKey=passKey)
        decryptedData = imageCrypt.decrypt(filename=filename, filepath=filepath, shifts=[shift], cipherUsed="caesar")

        end = time.time()
        timeTaken = end - start

    return decryptedData, timeTaken


def encrypt(passKey, dataformat, cipherMode, plaintext=None, filename=None, filepath=None):
    return encryptCheck(passKey=passKey, dataformat=dataformat, plaintext=plaintext,
        filename=filename, filepath=filepath, cipherMode=cipherMode)


def decrypt(passKey, dataformat, cipherMode, ciphertext=None, filename=None, filepath=None):
    return decryptCheck(passKey=passKey, dataformat=dataformat, ciphertext=ciphertext,
        filename=filename, filepath=filepath, cipherMode=cipherMode)
