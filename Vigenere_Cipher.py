# Vigenere Cipher Algorithm

"""
Padlock Encryption Software
Copyright 2019

Created by: Suraj Kothari
For A-level Computer Science
at Woodhouse College.
"""

import imageCrypt
import base64
import itertools
import os
import time


def getShiftValuesForImage(passKey):
    """ Returns a list of ASCII values for each character in the passkey for image encryption and decryption """

    return [ord(char) for char in passKey]


def getPassKeyString_classic(text, passKey):
    # A generator cycling through the characters in the pass key
    passKeyCycle = itertools.cycle(passKey)

    passKeyString = ""

    for t in text:
        if t.isalpha():
            nextKey = next(passKeyCycle)  # Gets the next key character
            passKeyString += nextKey

        else:
            # Add on any special characters WITHOUT incrementing the key character
            passKeyString += t

    return passKeyString


def getPassKeyString_ASCII(text, passKey):
    """
    Returns the special pass-key-string.

    This section calculates the pass-key-string to match the message length.

    Let the passkey be: king
    Let the message be: Hide in the forest.
    The pass-key-string length should match the length of the message like this:

    k i n g k i n g k i n g k i n g k i
    H i d e   i n   t h e   f o r e s t

    Here, the passkey (king) is repeated 4 whole times.
    This is the result of: len(message) DIV len(passkey).
    The (2) extra characters to fill the rest of the message are: k i
    The (2) comes from the result of: len(message) MOD len(passkey).

    The pass-key-string is the concatenation of the passkey repeated
    the (whole number of times + the remaining characters):
    ("king" * 4) + ki
    (kingkingkingkingki)
    """

    # A generator cycling through the characters in the pass key
    passKeyCycle = itertools.cycle(passKey)

    passKeyString = ""

    for t in text:
        nextKey = next(passKeyCycle)  # Gets the next key character
        passKeyString += nextKey

    return passKeyString


def encryptMessage_CLASSIC(plaintext, passKey):
    """ Encrypts a plaintext with the passkey in CLASSIC mode """

    cipherText = ""

    passKeyString = getPassKeyString_classic(text=plaintext, passKey=passKey)

    alphabet = "abcdefghijklmnopqrstuvwxyz"

    # Iterates through the pass-key-string and the plaintext simultaneously
    for x, (keyChar, plaintextChar) in enumerate(list(zip(passKeyString, plaintext))):
        if plaintextChar.lower() in alphabet:
            if plaintextChar.isupper():
                # Gets the letter position for each letter in the pass key string
                passKeyString_letter = alphabet.index(keyChar.lower()) + 1

                # Gets the letter position of each plain text character
                character_letter = alphabet.index(plaintextChar.lower()) + 1

                # Gets new position of encrypted character in the alphabet
                shiftedValue = (((character_letter - 1) + (passKeyString_letter - 1)) % 26) + 1

                # Gets the character at this new position
                newChar = alphabet[shiftedValue - 1]

                # Concatenates each encrypted character onto the plaintext string
                cipherText += newChar.upper()

            else:
                # Gets the letter position for each letter in the pass key string
                passKeyString_letter = alphabet.index(keyChar.lower()) + 1

                # Gets the letter position of each plain text character
                character_letter = alphabet.index(plaintextChar.lower()) + 1

                # Gets new position of encrypted character in the alphabet
                shiftedValue = (((character_letter - 1) + (passKeyString_letter - 1)) % 26) + 1

                # Gets the character at this new position
                newChar = alphabet[shiftedValue - 1]

                # Concatenates each encrypted character onto the plaintext string
                cipherText += newChar
        else:
            # Any non-alphabetical character is just added
            cipherText += plaintextChar

    return cipherText


def encryptMessage_ASCII(plaintext, passKey):
    """ Encrypts a plaintext with the passkey in ASCII mode """

    cipherText = ""
    passKeyString = getPassKeyString_ASCII(text=plaintext, passKey=passKey)

    # Iterates through the pass-key-string and the plaintext simultaneously
    for x, (keyChar, plaintextChar) in enumerate(list(zip(passKeyString, plaintext))):
        # Gets the ASCII value for each character in the pass key string
        passKeyString_ASCII = ord(keyChar)

        # Gets ASCII value of each plain text character
        character_ASCII = ord(plaintextChar)

        # Gets new position of encrypted character in ASCII
        shiftedValue = (((character_ASCII - 32) + (passKeyString_ASCII - 32)) % 95) + 32

        # Gets the character at this new position
        newChar = chr(shiftedValue)

        # Concatenates each encrypted character onto the plaintext string
        cipherText += newChar

    return cipherText


def decryptMessage_CLASSIC(ciphertext, passKey):
    """ Decrypts a ciphertext with the passkey in CLASSIC mode """

    plainText = ""

    passKeyString = getPassKeyString_classic(text=ciphertext, passKey=passKey)

    alphabet = "abcdefghijklmnopqrstuvwxyz"

    # Iterates through the pass-key-string and the plaintext simultaneously
    for x, (keyChar, ciphertextChar) in enumerate(list(zip(passKeyString, ciphertext))):
        if ciphertextChar.lower() in alphabet:
            if ciphertextChar.isupper():
                # Gets the letter position for each letter in the pass key string
                passKeyString_letter = alphabet.index(keyChar.lower()) + 1

                # Gets the letter position of each plain text character
                character_letter = alphabet.index(ciphertextChar.lower()) + 1

                # Gets new position of encrypted character in the alphabet
                shiftedValue = (((character_letter - 1) - (passKeyString_letter - 1)) % 26) + 1

                # Gets the character at this new position
                newChar = alphabet[shiftedValue - 1]

                # Concatenates each encrypted character onto the plaintext string
                plainText += newChar.upper()

            else:
                # Gets the letter position for each letter in the pass key string
                passKeyString_letter = alphabet.index(keyChar.lower()) + 1

                # Gets the letter position of each ciphertext character
                character_letter = alphabet.index(ciphertextChar.lower()) + 1

                # Gets new position of encrypted character in the alphabet
                shiftedValue = (((character_letter - 1) - (passKeyString_letter - 1)) % 26) + 1

                # Gets the character at this new position
                newChar = alphabet[shiftedValue - 1]

                # Concatenates each decrypted character onto the plaintext string
                plainText += newChar
        else:
            # Any non-alphabetical character is just added
            plainText += ciphertextChar

    return plainText


def decryptMessage_ASCII(ciphertext, passKey):
    """ Decrypts a ciphertext with the passkey in ASCII mode """

    plainText = ""
    passKeyString = getPassKeyString_ASCII(text=ciphertext, passKey=passKey)

    # Iterates through the pass-key-string and the ciphertext simultaneously
    for x, (keyChar, ciphertextChar) in enumerate(list(zip(passKeyString, ciphertext))):
        # Finds the ASCII value for each character in the pass key string
        passKeyString_ASCII = ord(keyChar)

        # Gets ASCII value of each ciphertext character.
        character_ASCII = ord(ciphertextChar)

        # Gets position of decrypted character in ASCII
        shiftedValue = (((character_ASCII - 32) - (passKeyString_ASCII - 32)) % 95) + 32

        # Gets the character at this position
        newChar = chr(shiftedValue)

        # Concatenates each decrypted character onto the ciphertext string
        plainText += newChar

    return plainText


def encryptFile(filename, filepath, passKey, cipherMode):
    """ Encrypts the contents of a text file using base64 """

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

    newFilename = "{}/{}_{}_ENC.txt".format(filepath, filename[:-4], 'vigenere')

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

    Encrypted = encryptMessage_ASCII(plaintext=encoded, passKey=passKey)

    extension = os.path.splitext(filename)[1]
    eLength = len(extension)
    newFilename = "{}/{}_{}_Base64_ENC{}".format(filepath, filename[:-eLength], 'vigenere', extension)

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
        newFilename = "{}/{}_{}_DEC.txt".format(filepath, filename[:-4], 'vigenere')

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
        newFilename = "{}/{}_{}_Base64_DEC{}".format(filepath, filename[:-eLength], 'vigenere', extension)

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

        shifts = getShiftValuesForImage(passKey=passKey)
        encryptedData = imageCrypt.encrypt(filename=filename, filepath=filepath, shifts=shifts, cipherUsed="vigenere")

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

        shift = getShiftValuesForImage(passKey=passKey)
        decryptedData = imageCrypt.decrypt(filename=filename, filepath=filepath, shifts=shift, cipherUsed="vigenere")

        end = time.time()
        timeTaken = end - start

    return decryptedData, timeTaken


def encrypt(passKey, dataformat, cipherMode, plaintext=None, filename=None, filepath=None):
    return encryptCheck(passKey, dataformat, plaintext=plaintext, filename=filename, filepath=filepath,
        cipherMode=cipherMode)


def decrypt(passKey, dataformat, cipherMode, ciphertext=None, filename=None, filepath=None):
    return decryptCheck(passKey, dataformat, ciphertext=ciphertext, filename=filename, filepath=filepath,
        cipherMode=cipherMode)
