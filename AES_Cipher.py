# AES Cipher Algorithm

"""
Padlock Encryption Software
Copyright 2019

Created by: Suraj Kothari
For A-level Computer Science
at Woodhouse College.
"""

import imageCrypt
import encryptionBlocks
import base64
import os
import time


def getShiftKeyForImage(passKey):
    """ Returns a list of denary values converted from their hexed representation of the round keys """

    denaryOfRoundKeys = []

    # Converts the passkey into a hex string
    hexedKey = getHexedKey(key=passKey)

    # Runs a process on the hexed key to generate 16 sub-keys
    roundKeys = generateRoundKeys(key=hexedKey)

    # Converts the hex value of each round key to binary
    for r in roundKeys:
        wholeRoundKey = "".join(r)
        denary = int(wholeRoundKey, 16)
        denaryOfRoundKeys.append(denary)

    return denaryOfRoundKeys


def getHexedKey(key):
    """ Returns the key in a hex form of exact size: 32 hex characters """

    # Creates a list of each character from the key
    key = list(key)

    # Converts each character to hex in the list
    hexedCharsList = [hex(ord(char))[2:] for char in key]

    # Converts list into a string
    hexedKey = "".join(hexedCharsList)

    # Adds padding if key is shorter than 32 hex characters
    if len(hexedKey) < 32:
        padding = 32 - len(hexedKey)
        hexedKey += ("00" * padding)

    # Truncates key if it is longer than 32 hex characters
    if len(hexedKey) > 32:
        hexedKey = hexedKey[0:32]

    # Separates the hexed string into individual hex bytes
    hexedList = [hexedKey[i:i+2] for i in range(0, len(hexedKey), 2)]

    print("".join(hexedList))
    return hexedList


def getHexedPlainText(plainText):
    """ Returns the plaintext in hex form and separates it into blocks of 32 into a list. """

    # Creates a list of each character from the plaintext
    plainText = list(plainText)

    # Converts each character, in the plaintext, to hex from the list
    hexedCharsList = [hex(ord(char))[2:] for char in plainText]

    # Concatenates the list into a string
    hexedPlainText = "".join(hexedCharsList)

    """
    Padds the hexed plaintext with 0s to the end to ensure it is
    a multiple of 32 hexadecimal characters.
    """

    length = len(hexedPlainText)

    # Only add the 0s if the length is not a multiple of 32
    if length % 32 != 0:
        """
        The ammount of padding is determined by finding
        the next multiple of 16 closest to the length: ((length // 16) + 1).
        By subtracting this multiple from the actual length, it will give
        the number of 0s needed to make the length a multiple of 16.
        """

        padding = ((((length // 32) + 1) * 32) - length)

        # Adds the appropriate number of 0s onto the end of the hexed plaintext
        hexedPlainText += ("0" * padding)

    # Separates the hexed plaintext into blocks of 32
    hexedPlainText32 = [hexedPlainText[i:i+32] for i in range(0, len(hexedPlainText), 32)]

    # Separates the individual hex blocks of 32 into pairs of bytes
    hexedPlainTextBytes = []

    for h in hexedPlainText32:
        # Separates each hexed plaintext block into individual hex bytes
        hByte = [h[i:i+2] for i in range(0, len(h), 2)]
        hexedPlainTextBytes.append(hByte)


    return hexedPlainTextBytes


def circularLeftShift(a, n):
    """ Shifts (rotates) the list left by n """

    shiftedArray = a[n:] + a[:n]

    return shiftedArray


def circularRightShift(a, n):
    """ Shifts (rotates) the list right by n """

    shiftedArray = a[-n:] + a[:-n]

    return shiftedArray


def functionG(k, roundNum):
    AES_SBOX = encryptionBlocks.getAES_SBox()

    g = circularLeftShift(k, 1)  # Shifts left by 1
    g2 = []

    for i in g:
        partX = int(i[0], 16)
        partY = int(i[1], 16)
        g2.append(AES_SBOX[partX][partY])

    roundingConstants = ["01", "02", "04", "08", "10", "20", "40", "80", "1b", "36"]

    # Gets current rounding constant depending on the current round number
    rc = roundingConstants[roundNum]

    # XOR rounding constant
    g2[0] = hex(int(g2[0], 16) ^ int(rc, 16))[2:].zfill(2)

    return g2


def XOR_Array(L1, L2):
    """ XORs each pair of items from two lists """

    XOR_Array = []

    for i, j in zip(L1, L2):
        # Converts hex to denary
        denaryI = int(i, 16)
        denaryJ = int(j, 16)

        xor = hex(denaryI ^ denaryJ)[2:].zfill(2)
        XOR_Array.append(xor)

    return XOR_Array


def XOR_HEX(a, b):
    """ XORs two hex values """

    # Converts hex to denary
    denaryA = int(a, 16)
    denaryB = int(b, 16)

    xor = hex(denaryA ^ denaryB)[2:].zfill(2)

    return xor


def XOR_Matrices(m1, m2):
    """ XORs two matrices """

    newMatrix = [[0 for i in range(4)] for j in range(4)]

    # Iterate through matrices
    for i, (row1, row2) in enumerate(zip(m1, m2)):
        for j, (item1, item2) in enumerate(zip(row1, row2)):
            newItem = XOR_HEX(item1, item2)
            newMatrix[i][j] = newItem

    return newMatrix


def generateRoundKeys(key):
    """ Processes the hexed key to generate 16 individual sub-keys """

    # Initialises the set of round keys to start with the passKey
    roundKeys = [key]
    tempRoundKey = key

    for round in range(10):
        r = getNextRoundKey(tempRoundKey, round)
        roundKeys.append(r)
        tempRoundKey = r

    return roundKeys

def getNextRoundKey(k, roundNum):
    """ Gets the next round key, given the current one """

    # Splits the key into groups of 4
    w0 = list(k[0:4])
    w1 = list(k[4:8])
    w2 = list(k[8:12])
    w3 = list(k[12:16])

    w4 = XOR_Array(w0, functionG(w3, roundNum))
    w5 = XOR_Array(w4, w1)
    w6 = XOR_Array(w5, w2)
    w7 = XOR_Array(w6, w3)

    # Round key is the concatentation of w4, w5, w6, and w7
    w = w4 + w5 + w6 + w7

    return w


def getMatrix(m):
    """ Creates a matrix from a list """

    matrix = [[0 for i in range(4)] for j in range(4)]

    for i, x in enumerate(m):
        # Gets the row and col positions to place each item vertically in the matrix
        row = i % 4
        col = i // 4
        matrix[row][col] = x

    return matrix


def SBOX_Substitution(m):
    """ Substitutes each item with its SBOX representation """

    newMatrix = [[0 for i in range(4)] for j in range(4)]

    AES_SBOX = encryptionBlocks.getAES_SBox()

    # Iterate through matrix
    for i, row in enumerate(m):
        for j, item in enumerate(row):
            partX = int(item[0], 16)
            partY = int(item[1], 16)

            newItem = AES_SBOX[partX][partY]
            newMatrix[i][j] = newItem

    return newMatrix


def inverse_SBOX_Substitution(m):
    """ Substitutes each item with its SBOX representation """

    newMatrix = [[0 for i in range(4)] for j in range(4)]

    AES_SBOX = encryptionBlocks.getAES_I_SBox()

    # Iterate through matrix
    for i, row in enumerate(m):
        for j, item in enumerate(row):
            partX = int(item[0], 16)
            partY = int(item[1], 16)

            newItem = AES_SBOX[partX][partY]
            newMatrix[i][j] = newItem

    return newMatrix


def ShiftRows(m):
    """ Shifts each row of a given matrix by a certain ammount """

    newMatrix = []

    for i, row in enumerate(m):
        # Shifts the rows left by the index of the current row
        shiftedRow = circularLeftShift(row, i)
        newMatrix.append(shiftedRow)

    return newMatrix


def inverse_ShiftRows(m):
    """
    Shifts each row of a given matrix by a certain ammount.
    Used for decryption.
    """

    newMatrix = []

    for i, row in enumerate(m):
        # Shifts the rows left by the index of the current row
        shiftedRow = circularRightShift(row, i)
        newMatrix.append(shiftedRow)

    return newMatrix


def GF_MultiplyByTwo(a):
    """ Mutiplies the input number by two using Galois Field Mathematics """

    gm = a * 2  # Performs normal multiplication

    # Checks to see if result is greater than 8 bits. If so, omits any overflow
    gmBinary = bin(gm)[2:].zfill(8)
    if len(gmBinary) > 8:
        gmBinary = gmBinary[len(gmBinary)-8:]

    """
    If the first bit of the input number is 'set', the result of the
    previous calculation needs to be XORed with 27 (1B in hex).
    Otherwise, it doesn't change
    """

    aBinary = bin(a)[2:].zfill(8)
    if aBinary[0] == '1':
        gm = int(gmBinary, 2) ^ int("1b", 16)

    else:
        gm = int(gmBinary, 2)

    return gm


def mixColumnProcess(m):
    """
    Mix Column process involves multiplying the fixed matrix
    against the current State Matrix.
    """

    newMatrix = [[0 for i in range(4)] for j in range(4)]

    fixedMatrix = [[2, 3, 1, 1],
                   [1, 2, 3, 1],
                   [1, 1, 2, 3],
                   [3, 1, 1, 2]]

    rotatedMatrix = [[0 for i in range(4)] for j in range(4)]

    # Rotates input matrix to make it vertical
    for i, row in enumerate(m):
        for j, x in enumerate(row):
            # Flips matrix index positions in order to rotate matrix
            rotatedMatrix[j][i] = x

    XOR_result = 0

    for cycleCounter in range(4):
        for subCycleCounter in range(4):
            for subProcessCounter in range(4):
                x = fixedMatrix[cycleCounter][subProcessCounter]
                y = rotatedMatrix[subCycleCounter][subProcessCounter]

                if x == 1:
                    XOR_part = int(y, 16)
                elif x == 2:
                    XOR_part = GF_MultiplyByTwo(int(y, 16))
                elif x == 3:
                    """
                    Multipling by 3 in the Galois Field is the same as
                    multiplying by 2 (in the Galois Field) and XORing the result
                    with the input itself.
                    """
                    XOR_part = GF_MultiplyByTwo(int(y, 16)) ^ int(y, 16)

                XOR_result ^= XOR_part

            mixColumnResult = hex(XOR_result)[2:].zfill(2)
            XOR_result = 0

            newMatrix[cycleCounter][subCycleCounter] = mixColumnResult

    return newMatrix


def inverse_mixColumnProcess(m):
    """
    Mix Column process involves multiplying the fixed matrix
    against the current State Matrix. Used for decryption.
    """

    newMatrix = [[0 for i in range(4)] for j in range(4)]

    # Inverse fixed matrix
    fixedMatrix = [[14, 11, 13, 9],
                   [9, 14, 11, 13],
                   [13, 9, 14, 11],
                   [11, 13, 9, 14]]

    rotatedMatrix = [[0 for i in range(4)] for j in range(4)]

    # Rotates input matrix to make it vertical
    for i, row in enumerate(m):
        for j, x in enumerate(row):
            # Flips matrix index positions in order to rotate matrix
            rotatedMatrix[j][i] = x

    XOR_result = 0

    for cycleCounter in range(4):
        for subCycleCounter in range(4):
            for subProcessCounter in range(4):
                x = fixedMatrix[cycleCounter][subProcessCounter]
                y = rotatedMatrix[subCycleCounter][subProcessCounter]

                # For decryption
                if x == 9:
                    XOR_part = GF_MultiplyByTwo(GF_MultiplyByTwo(
                        GF_MultiplyByTwo(int(y, 16)))) ^ int(y, 16)
                elif x == 11:
                    XOR_part = GF_MultiplyByTwo(
                        GF_MultiplyByTwo(
                            GF_MultiplyByTwo(int(y, 16))) ^ int(y, 16)) ^ int(y, 16)
                elif x == 13:
                    XOR_part = GF_MultiplyByTwo(
                        GF_MultiplyByTwo(
                            GF_MultiplyByTwo(int(y, 16)) ^ int(y, 16))) ^ int(y, 16)
                elif x == 14:
                    XOR_part = GF_MultiplyByTwo(
                        GF_MultiplyByTwo(
                            GF_MultiplyByTwo(int(y, 16)) ^ int(y, 16)) ^ int(y, 16))

                XOR_result ^= XOR_part

            mixColumnResult = hex(XOR_result)[2:].zfill(2)
            XOR_result = 0

            newMatrix[cycleCounter][subCycleCounter] = mixColumnResult

    return newMatrix


def getTextFromMatrix(m):
    """ Converts the final matrix into a string """

    rotatedMatrix = [[0 for i in range(4)] for j in range(4)]

    # Rotates input matrix to make it horizontal
    for i, row in enumerate(m):
        for j, x in enumerate(row):
            # Flips matrix index positions in order to rotate matrix
            rotatedMatrix[j][i] = x

    textString = ""

    for r in rotatedMatrix:
        textString += "".join(r)

    return textString


def getPlainTextFromHex(p):
    """ Gets ASCII string from hex for plaintext """

    # Groups the hex values into groups of twos
    bytes = [p[i:i+2] for i in range(0, len(p), 2)]

    # Converts each hex part to ASCII
    decryptedPart = [chr(int(b, 16)) for b in bytes]

    # Joins the characters in the list of ASCII characters
    decryptedPart = "".join(decryptedPart)

    return decryptedPart


def encryptMessage(plaintext, passKey):
    """Takes in a plaintext and passkey and returns the ciphertext"""

    # Converts inputs to hex
    hexedKey = getHexedKey(key=passKey)
    hexedPlainText = getHexedPlainText(plainText=plaintext)

    """ 1. Gets all 10 roundkeys """

    roundKeys = generateRoundKeys(key=hexedKey)

    cipherTextFinal = ""

    # Iterates over each block of 32 hex bytes in the hexed plaintext
    for hexBlock in hexedPlainText:
        # Converts plaintext list to matrix
        plaintextMatrix = getMatrix(hexBlock)

        # Initial state matrix
        stateMatrix = plaintextMatrix

        for i, R in enumerate(roundKeys):
            """ 2. Roundkey addition using plaintext matrix and key matrix """

            roundMatrix = getMatrix(R)

            stateMatrix = XOR_Matrices(stateMatrix, roundMatrix)

            """ 3. Substitution of AES SBOX of state matrix """

            stateMatrix = SBOX_Substitution(stateMatrix)

            """ 4. Shift rows of state matrix """

            stateMatrix = ShiftRows(stateMatrix)

            # During the last round, mix columns is not performed
            if i != 9:
                """ 5. Mix Columns of state matrix"""

                stateMatrix = mixColumnProcess(stateMatrix)

            else:
                """ 6. Add round key process"""

                # In the last round, the final round key is added instead
                stateMatrix = XOR_Matrices(stateMatrix, getMatrix(roundKeys[i + 1]))
                break

        finalCiphertextMatrix = stateMatrix

        # Converts plaintext matrix to string
        cipherText = getTextFromMatrix(finalCiphertextMatrix)

        cipherTextFinal += cipherText

    return cipherTextFinal.upper()


def decryptMessage(ciphertext, passKey):
    """Takes in a ciphertext and passkey and returns the plaintext"""

    # Converts inputs to hex
    hexedKey = getHexedKey(key=passKey)

    # Separates the hexed ciphertext into blocks of 32 into a list
    hexedCipherText32 = [ciphertext[i:i+32] for i in range(0, len(ciphertext), 32)]

    # Separates the individual hex blocks of 32 into pairs of bytes
    hexedCipherTextBytes = []

    for h in hexedCipherText32:
        hByte = [h[i:i+2] for i in range(0, len(h), 2)]
        hexedCipherTextBytes.append(hByte)

    """ 1. Gets all 10 roundkeys """

    roundKeys = generateRoundKeys(hexedKey)

    plainTextFinal = ""

    # Iterates over each block of 32 hex bytes in the hexed ciphertext
    for hexBlock in hexedCipherTextBytes:
        # Converts ciphertext list to matrix
        ciphertextMatrix = getMatrix(hexBlock)

        # Initial state matrix
        stateMatrix = ciphertextMatrix

        # For decryption, iterate over each subkey in reverse order
        for i, R in reversed(list(enumerate(roundKeys))):
            roundMatrix = getMatrix(R)

            """ Add round key process"""

            stateMatrix = XOR_Matrices(stateMatrix, roundMatrix)

            # In The first round, mix columns is not performed
            if i == 10:
                """ Shift rows of state matrix """

                stateMatrix = inverse_ShiftRows(stateMatrix)

                """ Substitution of AES SBOX of state matrix """

                stateMatrix = inverse_SBOX_Substitution(stateMatrix)

            else:
                """ Mix Columns of state matrix"""

                stateMatrix = inverse_mixColumnProcess(stateMatrix)

                """ Shift rows of state matrix """

                stateMatrix = inverse_ShiftRows(stateMatrix)

                """ Substitution of AES SBOX of state matrix """

                stateMatrix = inverse_SBOX_Substitution(stateMatrix)

                if i == 1:
                    """ Roundkey addition using plaintext matrix and key matrix """

                    roundMatrix = getMatrix(R)

                    # In the second last round, the final round key is added instead
                    stateMatrix = XOR_Matrices(stateMatrix, getMatrix(roundKeys[i - 1]))

                    break

        finalPlaintextMatrix = stateMatrix

        # Converts plaintext matrix to string
        plainText = getTextFromMatrix(finalPlaintextMatrix)

        # Converts plaintext in hex to ASCII string
        plainTextFinal += getPlainTextFromHex(plainText)

    return plainTextFinal


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

    newFilename = "{}/{}_{}_ENC.txt".format(filepath, filename[:-4], 'AES')

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
    newFilename = "{}/{}_{}_Base64_ENC{}".format(filepath, filename[:-eLength], 'AES', extension)

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
        newFilename = "{}/{}_{}_DEC.txt".format(filepath, filename[:-4], 'AES')

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
        newFilename = "{}/{}_{}_Base64_DEC{}".format(filepath, filename[:-eLength], 'AES', extension)

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

        shift = getShiftKeyForImage(passKey=passKey)
        encryptedData = imageCrypt.encrypt(filename=filename, filepath=filepath, shifts=shift, cipherUsed="AES")

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
        shift = getShiftKeyForImage(passKey=passKey)

        decryptedData = imageCrypt.decrypt(filename=filename, filepath=filepath, shifts=shift, cipherUsed="AES")

        end = time.time()
        timeTaken = end - start

    return decryptedData, timeTaken


def encrypt(passKey, dataformat, cipherMode=None, plaintext=None, filename=None, filepath=None):
    return encryptCheck(passKey, dataformat, cipherMode=cipherMode, plaintext=plaintext,
        filename=filename, filepath=filepath)


def decrypt(passKey, dataformat, cipherMode=None, ciphertext=None, filename=None, filepath=None):
    return decryptCheck(passKey, dataformat, cipherMode=cipherMode, ciphertext=ciphertext,
        filename=filename, filepath=filepath)
