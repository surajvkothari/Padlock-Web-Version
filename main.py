"""
Padlock Web Version - Python with Flask
Author: Suraj Kothari
"""

from flask import Flask, render_template, request, Markup
import multicrypt
import time
from werkzeug.utils import secure_filename
import os
import random

app = Flask(__name__)
UPLOAD_PATH = "static/uploads"
app.config['UPLOAD_PATH'] = UPLOAD_PATH

def clear_files():
    """ Clear all files from the uploads directory when goes on site """
    for filename in os.listdir(UPLOAD_PATH):
        os.remove(os.path.join(UPLOAD_PATH, filename))

@app.route('/padlock', methods=['POST', 'GET'])
def padlock():
    # Remove files stored in uploads
    #clear_files()

    if request.method == "POST":
        timeTaken = 0
        outputText = ""
        outputFilepath = ""
        outputFilename = ""
        failed = ""

        process = request.form["processInput"]
        dataFormat = request.form["dataFormatInput"]
        cipher = request.form["cipherInput"]
        cipherMode = request.form["cipherModeInput"]
        inputArea = request.form["inputArea"]
        fileUploaded = request.files["fileInput"]

        if cipher == "Triple DES Cipher":
            key1 = request.form["keyInput"]
            key2 = request.form["keyInput2"]
            key3 = request.form["keyInput3"]

            key = (key1, key2, key3)
        else:
            key = request.form["keyInput"]


        if process == "encrypt":
            if dataFormat == "Messages":
                try:
                    outputText, timeTaken = multicrypt.encrypt(plaintext=inputArea, passKey=key, cipher=cipher,
                            dataformat=dataFormat, cipherMode=cipherMode)
                except Exception as e:
                    outputText = "ERROR: Encryption failed!"
                    failed = "failed"
                    print(e)

            elif dataFormat == "Files":
                filename = secure_filename(fileUploaded.filename)
                # Save the file in the upload folder
                fileUploaded.save(os.path.join(app.config['UPLOAD_PATH'], filename))
                try:
                    outputFilepath, timeTaken = multicrypt.encrypt(filename=filename,
                        filepath=UPLOAD_PATH, passKey=key, cipher=cipher,
                            dataformat=dataFormat, cipherMode=cipherMode)

                    # Remove path from output file and return just the filename
                    outputFilename = os.path.basename(outputFilepath)
                    outputText = f"Filename: {outputFilename}"
                except Exception as e:
                    outputText = "ERROR: File encryption failed!"
                    failed = "failed"
                    print(e)

            elif dataFormat == "Images":
                filename = secure_filename(fileUploaded.filename)
                # Save the file in the upload folder
                fileUploaded.save(os.path.join(app.config['UPLOAD_PATH'], filename))
                try:
                    outputFilepath, timeTaken = multicrypt.encrypt(filename=filename,
                        filepath=UPLOAD_PATH, passKey=key, cipher=cipher,
                            dataformat=dataFormat)

                    # Remove path from output file and return just the filename
                    outputFilename = os.path.basename(outputFilepath)
                    outputText = f"Filename: {outputFilename}"
                except Exception as e:
                    outputText = "ERROR: Image encryption failed!"
                    failed = "failed"
                    print(e)
        else:
            """
            Decryption
            """
            if dataFormat == "Messages":
                try:
                    outputText, timeTaken = multicrypt.decrypt(ciphertext=inputArea, passKey=key, cipher=cipher,
                            dataformat=dataFormat, cipherMode=cipherMode)
                except Exception as e:
                    outputText = "ERROR: Decryption failed!"
                    failed = "failed"
                    print(e)

            elif dataFormat == "Files":
                filename = secure_filename(fileUploaded.filename)
                # Save the file in the upload folder
                fileUploaded.save(os.path.join(app.config['UPLOAD_PATH'], filename))
                try:
                    outputFilepath, timeTaken = multicrypt.decrypt(filename=filename,
                        filepath=UPLOAD_PATH, passKey=key, cipher=cipher,
                            dataformat=dataFormat, cipherMode=cipherMode)

                    # Remove path from output file and return just the filename
                    outputFilename = os.path.basename(outputFilepath)
                    outputText = f"Filename: {outputFilename}"
                except Exception as e:
                    outputText = "ERROR: File decryption failed!"
                    failed = "failed"
                    print(e)

            elif dataFormat == "Images":
                filename = secure_filename(fileUploaded.filename)
                # Save the file in the upload folder
                fileUploaded.save(os.path.join(app.config['UPLOAD_PATH'], filename))
                try:
                    outputFilepath, timeTaken = multicrypt.decrypt(filename=filename,
                        filepath=UPLOAD_PATH, passKey=key, cipher=cipher,
                            dataformat=dataFormat)

                    # Remove path from output file and return just the filename
                    outputFilename = os.path.basename(outputFilepath)
                    outputText = f"Filename: {outputFilename}"
                except Exception as e:
                    outputText = "ERROR: Image decryption failed!"
                    failed = "failed"
                    print(e)

        # Format time is it is not 0
        if timeTaken != 0:
            timeTakenString = "Time taken: " + time.strftime('%M:%S', time.gmtime(timeTaken))
        else:
            timeTakenString = ""

        # If the filepath is defined, then add a random integer to the end
        # This will prevent caching in the browser for multiple encryption/decryptions
        if outputFilepath:
            outputFilepath += "?temp=" + str(random.randint(1, 1000))

        # Remove non-ascii characters usually found when decrypting
        outputText.encode("ascii", errors="ignore")

        return render_template("padlock.html", inputText=inputArea,
            outputText=outputText, failed=failed, timeTakenString=timeTakenString,
            dataFormatInput=dataFormat, cipherInput=cipher, cipherModeInput=cipherMode,
            outputFilepath=outputFilepath, outputFilename=outputFilename)

    # Initial template when site is started up
    return render_template("padlock.html", dataFormatInput="Messages",
        cipherInput="Caesar Cipher", cipherModeInput="Classic")
