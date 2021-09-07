# Image encryption module

"""
Padlock Encryption Software
Copyright 2019

Created by: Suraj Kothari
For A-level Computer Science
at Woodhouse College.
"""

from PIL import Image
import itertools
import time


def getEncryptedPixel(input_pixel, shift, cipherUsed):
    """Encrypts the individual pixels with a shift value"""

    # Gets the number of pixel values. JPGs have 3 and PNGs have 4.
    numberOfPixelValues = len(input_pixel)

    pixel = input_pixel

    # Sets the R, G, B values of each pixel
    R = pixel[0]
    G = pixel[1]
    B = pixel[2]

    """
    For Medium and Strong ciphers, if the shift is too small, it is increased
    to avoid small shifts in colours
    """

    if cipherUsed in ("DES", "TripleDES", "AES", "RC4"):
        if (shift % 256) < 20 or (256 - (shift % 256)) < 20:
            shift += 50

    # Shifts each colour of the pixel by the shift value to get the new pixel values
    colourRed = (R + shift) % 256
    colourGreen = (G + shift) % 256
    colourBlue = (B + shift) % 256

    # Checks if the image type is PNG and if Triple DES encryption is not used
    if numberOfPixelValues == 4:
        # PNG images have an alpha channel
        A = pixel[3]
        alpha = (A + shift) % 256

        return (colourRed, colourGreen, colourBlue, alpha)
    else:
        return (colourRed, colourGreen, colourBlue)


def getDecryptedPixel(input_pixel, shift, cipherUsed):
    """Encrypts the individual pixels with a shift value"""

    # Gets the number of pixel values. JPGs have 3 and PNGs have 4.
    numberOfPixelValues = len(input_pixel)

    pixel = input_pixel

    # Sets the R,G,B values of each pixel
    R = pixel[0]
    G = pixel[1]
    B = pixel[2]

    """
    For Medium and Strong ciphers, if the shift is too small, it is increased
    to avoid small shifts in colours
    """

    if cipherUsed in ("DES", "TripleDES", "AES", "RC4"):
        if (shift % 256) < 20 or (256 - (shift % 256)) < 20:
            shift += 50

    # Shifts each colour of the pixel by the shift to get the new pixel values
    colourRed = (R - shift) % 256
    colourGreen = (G - shift) % 256
    colourBlue = (B - shift) % 256

    """
    Checks if the number of pixel values is 4, as that means the original
    image was a PNG and we need to decrypt its alpha channel as well.
    """

    if numberOfPixelValues == 4:
        # PNG images have an alpha channel
        A = pixel[3]
        alpha = (A - shift) % 256

        return (colourRed, colourGreen, colourBlue, alpha)
    else:
        return (colourRed, colourGreen, colourBlue)


def getPixelData(width, height, shifts, cipherUsed):
    """Creates a generator function to get pixel and key tuples"""

    """
    In AES, the pixels are extracted vertically.
    The image is iterated column wise instead of horizontally.
    """
    if cipherUsed in ("AES", "RC4"):

        """
        Swaps the inner loops of
        itertools.product to iterate column-wise.
        """

        verticalGenerator = ((x, y) for y in height for x in width)

        for pixelValue, key in zip(verticalGenerator, itertools.cycle(shifts)):
            # Returns a tuple: (pixelX, pixelY, key)
            yield (*pixelValue, key)

    else:
        """
        Iterates through the pixel values of the width and height combined from itertools.product()
        then iterates through the shifts in a cycle using itertools.cycle()
        """

        for pixelValue, key in zip(itertools.product(width, height), itertools.cycle(shifts)):
            # Returns a tuple: (pixelX, pixelY, key)
            yield (*pixelValue, key)


def encryptPixels(width, height, shifts, originalImagePixelData, copyImagePixelData, cipherUsed, isTripleDES=None):
    # In Triple DES, the shifts come in a pair
    if isTripleDES is True:
        shifts_list = shifts[0]
        second_shifts = shifts[1]
        third_shifts = shifts[2]
    else:
        shifts_list = shifts

    for pixelTuple in getPixelData(width=width, height=height, shifts=shifts_list, cipherUsed=cipherUsed):
        # Sets the pixel's X and Y values; and the key value, from the tuple given by the generator function
        pixelX, pixelY, shift = pixelTuple[0], pixelTuple[1], pixelTuple[2]

        # Gets each pixel value from the original image
        pixel = originalImagePixelData[pixelX, pixelY]

        if isTripleDES is True:
            E_pixel_temp = getEncryptedPixel(input_pixel=pixel, shift=shift, cipherUsed=cipherUsed)

            shift2 = second_shifts[shifts_list.index(shift)]

            D_pixel = getDecryptedPixel(input_pixel=E_pixel_temp, shift=shift2, cipherUsed=cipherUsed)

            shift3 = third_shifts[shifts_list.index(shift)]

            E_pixel = getEncryptedPixel(input_pixel=D_pixel, shift=shift3, cipherUsed=cipherUsed)

        else:
            E_pixel = getEncryptedPixel(input_pixel=pixel, shift=shift, cipherUsed=cipherUsed)

        # Stores the changes onto the copied image’s pixel map
        copyImagePixelData[pixelX, pixelY] = E_pixel


def decryptPixels(width, height, shifts, encryptedImagePixelData, copyImagePixelData, cipherUsed, isTripleDES=None):
    # In Triple DES, the shifts come in a pair
    if isTripleDES is True:
        shifts_list = shifts[0]
        second_shifts = shifts[1]
        third_shifts = shifts[2]
    else:
        shifts_list = shifts

    for pixelTuple in getPixelData(width=width, height=height, shifts=shifts_list, cipherUsed=cipherUsed):
        # Sets the pixel's X and Y values; and the key value, from the tuple given by the generator function
        pixelX, pixelY, shift = pixelTuple[0], pixelTuple[1], pixelTuple[2]

        # Gets each pixel value from the original image
        pixel = encryptedImagePixelData[pixelX, pixelY]

        if isTripleDES is True:
            shift3 = third_shifts[shifts_list.index(shift)]

            D_pixel_temp = getDecryptedPixel(input_pixel=pixel, shift=shift3, cipherUsed=cipherUsed)

            shift2 = second_shifts[shifts_list.index(shift)]

            E_pixel = getEncryptedPixel(input_pixel=D_pixel_temp, shift=shift2, cipherUsed=cipherUsed)

            D_pixel = getDecryptedPixel(input_pixel=E_pixel, shift=shift, cipherUsed=cipherUsed)

        else:
            D_pixel = getDecryptedPixel(input_pixel=pixel, shift=shift, cipherUsed=cipherUsed)

        # Stores the changes onto the copied image’s pixel map
        copyImagePixelData[pixelX, pixelY] = D_pixel


def loadEncryption(filename, filepath, originalImage, imageFormat, shifts, cipherUsed):
    """Gets the image pixel data, manipulates the image, then saves it"""

    """
    Gets a pixel access object for the original image
    The pixel access object will behave like a 2D list
    which will allow the program to read and modify individual pixels.
    """

    originalImagePixelData = originalImage.load()

    # Makes a copy of the input image and loads the copied image's pixel map
    copyImage = Image.new(originalImage.mode, originalImage.size)
    copyImagePixelData = copyImage.load()

    # Gets the width and height of the copied image
    width = range(copyImage.size[0])
    height = range(copyImage.size[1])

    # Encrypts the image pixels
    if cipherUsed == "TripleDES":
        encryptPixels(width=width, height=height, shifts=shifts, originalImagePixelData=originalImagePixelData,
            copyImagePixelData=copyImagePixelData, cipherUsed=cipherUsed, isTripleDES=True)
    else:
        encryptPixels(width=width, height=height, shifts=shifts, originalImagePixelData=originalImagePixelData,
            copyImagePixelData=copyImagePixelData, cipherUsed=cipherUsed)

    # Closes the original image
    originalImage.close()

    """
    All the filenames are saved as .png, as JPG files perform
    lossy compression. This alters the encrypted pixels and is
    not beneficial when decrypting.
    """

    newFilename = "{}/{}_{}_ENC.png".format(filepath, filename[:-4], cipherUsed)

    # Saves the encrypted image and then close it
    copyImage.save(newFilename)
    copyImage.close()

    return newFilename


def loadDecryption(filename, filepath, shifts, cipherUsed):
    """Gets the image pixel data, manipulates the image, then saves it"""

    full_filename = filepath + "/" + filename
    inputImage = Image.open(full_filename)

    """
    Gets a pixel access object for the input image
    The pixel access object will behave like a 2D list
    which will allow the program to read and modify individual pixels.
    """

    encryptedImagePixelData = inputImage.load()

    # Makes a copy of the input image and loads the copied image's pixel map
    copyImage = Image.new(inputImage.mode, inputImage.size)
    copyPixelMap = copyImage.load()

    # Gets the width and height of the copied image
    width = range(copyImage.size[0])
    height = range(copyImage.size[1])

    # Decrypts the image pixels
    if cipherUsed == "TripleDES":
        decryptPixels(width=width, height=height, shifts=shifts, encryptedImagePixelData=encryptedImagePixelData,
            copyImagePixelData=copyPixelMap, cipherUsed=cipherUsed, isTripleDES=True)
    else:
        decryptPixels(width=width, height=height, shifts=shifts, encryptedImagePixelData=encryptedImagePixelData,
            copyImagePixelData=copyPixelMap, cipherUsed=cipherUsed)

    # Closes the input image
    inputImage.close()

    if "ENC" in filename:
        newFilename = "{}/{}".format(filepath, filename.replace("ENC", "DEC"))
    else:
        newFilename = "{}/{}_{}_DEC.png".format(filepath, filename[:-4], cipherUsed)

    # Saves the encrypted image
    copyImage.save(newFilename)
    copyImage.close()

    return newFilename


def encryptionImageHandler(filename, filepath, shifts, cipherUsed):
    """Checks if the original image needs to be converted to RGBA format"""

    full_filename = filepath + "/" + filename
    originalImage = Image.open(full_filename)

    # Gets the extension of the image
    extension = filename.split(".")[-1]

    # Checks if the image type is PNG and if Triple DES encryption is not used
    if extension == "png":
        # PNG images need to be converted to RGBA format
        originalImage = originalImage.convert("RGBA")

    encryptedData = loadEncryption(filename=filename, filepath=filepath, originalImage=originalImage,
        imageFormat=extension, shifts=shifts, cipherUsed=cipherUsed)

    return encryptedData


def encrypt(filename, filepath, shifts, cipherUsed):
    encryptedData = encryptionImageHandler(filename=filename, filepath=filepath, shifts=shifts, cipherUsed=cipherUsed)

    return encryptedData


def decrypt(filename, filepath, shifts, cipherUsed):
    decryptedData = loadDecryption(filename=filename, filepath=filepath, shifts=shifts, cipherUsed=cipherUsed)

    return decryptedData
