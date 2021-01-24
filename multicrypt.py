# Multicrypt organisation module

"""
Padlock Encryption Software
Copyright 2019

Created by: Suraj Kothari
For A-level Computer Science
at Woodhouse College.
"""

import Caesar_Cipher
import Vigenere_Cipher
import DES_Cipher
import AES_Cipher
import RC4_Cipher


def encrypt(passKey, cipher, dataformat, plaintext=None, filename=None, filepath=None, cipherMode=None):
    """ Checks the cipher used and returns the requested encrypted data """

    # If the data format is message, a plaintext argument will need to be passed.

    if dataformat == "Messages":
        if cipher == "Caesar Cipher":
            encryptedData = Caesar_Cipher.encrypt(plaintext=plaintext,
                passKey=passKey, dataformat=dataformat, cipherMode=cipherMode)

        elif cipher == "Vigenere Cipher":
            encryptedData = Vigenere_Cipher.encrypt(plaintext=plaintext,
                passKey=passKey, dataformat=dataformat, cipherMode=cipherMode)

        elif cipher == "DES Cipher":
            encryptedData = DES_Cipher.encrypt(plaintext=plaintext,
                passKey=passKey, dataformat=dataformat)

        elif cipher == "Triple DES Cipher":
            encryptedData = DES_Cipher.encrypt(plaintext=plaintext,
                passKey=passKey, dataformat=dataformat, isTripleDES=True)

        elif cipher == "AES Cipher":
            encryptedData = AES_Cipher.encrypt(plaintext=plaintext,
                passKey=passKey, dataformat=dataformat)

        elif cipher == "RC4 Cipher":
            encryptedData = RC4_Cipher.encrypt(plaintext=plaintext,
                passKey=passKey, dataformat=dataformat)

    # If the data format is either a file or an image, a filename argument will need to be passed.

    else:
        if cipher == "Caesar Cipher":
            encryptedData = Caesar_Cipher.encrypt(filename=filename,
                filepath=filepath, passKey=passKey, dataformat=dataformat, cipherMode=cipherMode)

        elif cipher == "Vigenere Cipher":
            encryptedData = Vigenere_Cipher.encrypt(filename=filename,
                filepath=filepath, passKey=passKey, dataformat=dataformat, cipherMode=cipherMode)

        elif cipher == "DES Cipher":
            encryptedData = DES_Cipher.encrypt(filename=filename,
                filepath=filepath, passKey=passKey, dataformat=dataformat, cipherMode=cipherMode)

        elif cipher == "Triple DES Cipher":
            encryptedData = DES_Cipher.encrypt(filename=filename, filepath=filepath,
                passKey=passKey, dataformat=dataformat, cipherMode=cipherMode, isTripleDES=True)

        elif cipher == "AES Cipher":
            encryptedData = AES_Cipher.encrypt(filename=filename,
                filepath=filepath, passKey=passKey, dataformat=dataformat, cipherMode=cipherMode)

        elif cipher == "RC4 Cipher":
            encryptedData = RC4_Cipher.encrypt(filename=filename,
                filepath=filepath, passKey=passKey, dataformat=dataformat, cipherMode=cipherMode)

    return encryptedData


def decrypt(passKey, cipher, dataformat, ciphertext=None, filename=None, filepath=None, cipherMode=None):
    """ Checks the cipher used and returns the requested decrypted data """

    # If the data format is message, a ciphertext argument will need to be passed.

    if dataformat == "Messages":
        if cipher == "Caesar Cipher":
            decryptedData = Caesar_Cipher.decrypt(ciphertext=ciphertext,
                passKey=passKey, dataformat=dataformat, cipherMode=cipherMode)

        elif cipher == "Vigenere Cipher":
            decryptedData = Vigenere_Cipher.decrypt(ciphertext=ciphertext,
                passKey=passKey, dataformat=dataformat, cipherMode=cipherMode)

        elif cipher == "DES Cipher":
            decryptedData = DES_Cipher.decrypt(ciphertext=ciphertext,
                passKey=passKey, dataformat=dataformat)

        elif cipher == "Triple DES Cipher":
            decryptedData = DES_Cipher.decrypt(ciphertext=ciphertext,
                passKey=passKey, dataformat=dataformat, isTripleDES=True)

        elif cipher == "AES Cipher":
            decryptedData = AES_Cipher.decrypt(ciphertext=ciphertext,
                passKey=passKey, dataformat=dataformat)

        elif cipher == "RC4 Cipher":
            decryptedData = RC4_Cipher.decrypt(ciphertext=ciphertext,
                passKey=passKey, dataformat=dataformat)


    # If the data format is either a file or an image, a filename argument will need to be passed.

    else:
        if cipher == "Caesar Cipher":
            decryptedData = Caesar_Cipher.decrypt(filename=filename,
                filepath=filepath, passKey=passKey, dataformat=dataformat, cipherMode=cipherMode)

        elif cipher == "Vigenere Cipher":
            decryptedData = Vigenere_Cipher.decrypt(filename=filename,
                filepath=filepath, passKey=passKey, dataformat=dataformat, cipherMode=cipherMode)

        elif cipher == "DES Cipher":
            decryptedData = DES_Cipher.decrypt(filename=filename,
                filepath=filepath, passKey=passKey, dataformat=dataformat, cipherMode=cipherMode)

        elif cipher == "Triple DES Cipher":
            decryptedData = DES_Cipher.decrypt(filename=filename, filepath=filepath,
                passKey=passKey, dataformat=dataformat, cipherMode=cipherMode, isTripleDES=True)

        elif cipher == "AES Cipher":
            decryptedData = AES_Cipher.decrypt(filename=filename,
                filepath=filepath, passKey=passKey, dataformat=dataformat, cipherMode=cipherMode)

        elif cipher == "RC4 Cipher":
            decryptedData = RC4_Cipher.decrypt(filename=filename,
                filepath=filepath, passKey=passKey, dataformat=dataformat, cipherMode=cipherMode)

    return decryptedData
