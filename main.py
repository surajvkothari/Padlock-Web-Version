"""
Padlock Web Version - Python with Flask
Author: Suraj Kothari
"""

from flask import Flask, render_template, request, Markup
import multicrypt
import time
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
UPLOAD_PATH = "static/uploads"
app.config['UPLOAD_PATH'] = UPLOAD_PATH

def clear_files():
    """ Clear all files from the uploads directory when goes on site """
    for filename in os.listdir(UPLOAD_PATH):
        os.remove(os.path.join(UPLOAD_PATH, filename))

@app.route('/padlock', methods=['POST', 'GET'])
def padlock():
    clear_files()

    if request.method == "POST":
        timeTaken = 0
        outputText = ""
        failed = ""
        outputFilePath = ""
        failed = "failed"

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
                    failed = ""
                except Exception as e:
                    outputText = "ERROR: Encryption failed!"
                    print(e)

            elif dataFormat == "Files":
                filename = secure_filename(fileUploaded.filename)
                # Save the file in path provided
                fileUploaded.save(os.path.join(app.config['UPLOAD_PATH'], filename))
                try:
                    outputFilePath, timeTaken = multicrypt.encrypt(filename=filename,
                        filepath=UPLOAD_PATH, passKey=key, cipher=cipher,
                            dataformat=dataFormat)
                    failed = ""
                    outputText = Markup("File encryption successful!<br>Filename: " + os.path.basename(outputFilePath))
                except Exception as e:
                    outputText = "ERROR: File encryption failed!"
                    print(e)

            elif dataFormat == "Images":
                filename = secure_filename(fileUploaded.filename)
                full_filepath = os.path.join(app.config['UPLOAD_PATH'], filename)
                # Save the file in path provided
                fileUploaded.save(full_filepath)
                try:
                    outputFilePath, timeTaken = multicrypt.encrypt(filename=filename,
                        filepath=UPLOAD_PATH, passKey=key, cipher=cipher,
                            dataformat=dataFormat)
                    failed = ""
                    outputText = Markup("Image encryption successful!<br>Filename: " + os.path.basename(outputFilePath))
                except Exception as e:
                    outputText = "ERROR: Image encryption failed!"
                    print(e)
        else:
            if dataFormat == "Messages":
                try:
                    outputText, timeTaken = multicrypt.decrypt(ciphertext=inputArea, passKey=key, cipher=cipher,
                            dataformat=dataFormat, cipherMode=cipherMode)
                    failed = ""
                except Exception as e:
                    outputText = "ERROR: Decryption failed!"
                    print(e)

            elif dataFormat == "Files":
                filename = secure_filename(fileUploaded.filename)
                # Save the file in path provided
                fileUploaded.save(os.path.join(app.config['UPLOAD_PATH'], filename))
                try:
                    outputFilePath, timeTaken = multicrypt.decrypt(filename=filename,
                        filepath=UPLOAD_PATH, passKey=key, cipher=cipher,
                            dataformat=dataFormat)
                    failed = ""
                    outputText = Markup("File decryption successful!<br>Filename: " + os.path.basename(outputFilePath))
                except Exception as e:
                    outputText = "ERROR: File decryption failed!"
                    print(e)

            elif dataFormat == "Images":
                filename = secure_filename(fileUploaded.filename)
                filepath = os.path.join(app.config['UPLOAD_PATH'], filename)
                # Save the file in path provided
                fileUploaded.save(filepath)
                try:
                    outputFilePath, timeTaken = multicrypt.decrypt(filename=filename,
                        filepath=UPLOAD_PATH, passKey=key, cipher=cipher,
                            dataformat=dataFormat)
                    failed = ""
                    outputText = Markup("Image decryption successful!<br>Filename: " + os.path.basename(outputFilePath))
                except Exception as e:
                    outputText = "ERROR: Image decryption failed!"
                    print(e)

        # Format time
        if timeTaken != 0:
            timeTakenString = "Time taken: " + time.strftime('%M:%S', time.gmtime(timeTaken))
        else:
            timeTakenString = ""

        return render_template("padlock.html", inputText=inputArea,
            outputText=outputText, failed=failed, timeTakenString=timeTakenString,
            dataFormatInput=dataFormat, cipherInput=cipher, cipherModeInput=cipherMode,
            outputImage=outputFilePath)

    # Initial template when site is started up
    return render_template("padlock.html", timeTaken="", dataFormatInput="Messages",
        cipherInput="Caesar Cipher", cipherModeInput="Classic", outputImage="")
