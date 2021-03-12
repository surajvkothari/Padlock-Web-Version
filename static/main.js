/*
Padlock Web Version - JavaScript
Author: Suraj Kothari
*/

window.onclick = function(event) {
    // Close any dropdown if the user clicks outside of it
    // Reference: https://www.w3schools.com/howto/howto_js_dropdown.asp
    if (!event.target.matches('.dropdown-btn')) {
        var dropdowns = document.getElementsByClassName("dropdown-body");
        for (var i = 0; i < dropdowns.length; i++) {
            var openDropdown = dropdowns[i];
            if (openDropdown.classList.contains('show')) {
                openDropdown.classList.remove('show');
            }
        }
    }
}

function initialiseSite() {
    /* Initialises the site upon refresh */
    if (document.getElementById("dataFormatInput").value == "Messages") {
        document.getElementById("outputFileArea").style.display = "none";
        // Set output button to a copy button
        document.getElementById("outputBtn").innerHTML = "Copy message";
        document.getElementById("outputBtn").classList.add("copy");
        // Hide image
        document.getElementById("outputImage").style.display = "none";
    }

    else if (document.getElementById("dataFormatInput").value == "Files") {
        document.getElementById("fileInputArea").style.display = "block";
        // Hide input and output text boxes
        document.getElementById("inputArea").style.display = "none";
        document.getElementById("outputArea").style.display = "none";

        // Show the file mode dividers for the cipher mode dropdown
        document.getElementById("fileModeDivider1").style.display = "block";
        document.getElementById("fileModeDivider2").style.display = "block";
        // Show Base64 mode
        document.getElementById("Base64ModeLabel").style.display = "block";

        if (document.getElementById("cipherModeInput").value == "Base64") {
            document.getElementById("uploadText").innerHTML = "Upload a file (any file type)";
            document.getElementById("fileInput").removeAttribute("accept");
        } else {
            document.getElementById("uploadText").innerHTML = "Upload a file (.TXT)";
            document.getElementById("fileInput").setAttribute("accept", ".txt");
        }

        document.getElementById("outputBtn").innerHTML = "Download File";
        // Hide image
        document.getElementById("outputImage").style.display = "none";
    }

    else if (document.getElementById("dataFormatInput").value == "Images") {
        document.getElementById("fileInputArea").style.display = "block";
        // Hide input and output text boxes
        document.getElementById("inputArea").style.display = "none";
        document.getElementById("outputArea").style.display = "none";
        document.getElementById("uploadText").innerHTML = "Upload an image (.PNG or .JPG)";
        document.getElementById("fileInput").setAttribute("accept", ".png,.jpg");
        document.getElementById("outputBtn").innerHTML = "Download Image";

        // Display image
        document.getElementById("outputImage").style.display = "block";
    }

    // Hide the extra keys if not Triple DES is selected
    if (document.getElementById("cipherInput").value == "Triple DES Cipher") {
        document.getElementById("tDESKeys").style.display = "block";
    } else {
        document.getElementById("tDESKeys").style.display = "none";
    }
}

// Set data format dropdown options
function showDataFormatDropdown() {document.getElementById("dataFormatDropdown").classList.toggle("show");}
function setMessageOption() {
    document.getElementById("activeDataFormat").innerHTML = "MESSAGES &#x25BC;";
    document.getElementById("dataFormatInput").setAttribute("value", "Messages");
    // Set output button to a copy button
    document.getElementById("outputBtn").classList.add("copy");
    document.getElementById("outputBtn").innerHTML = "Copy Message";
    // Show mode area and input/output text boxes
    document.getElementById("modeArea").style.display = "block";
    document.getElementById("inputArea").style.display = "block";
    document.getElementById("outputArea").style.display = "block";
    document.getElementById("inputArea").innerHTML = "";
    document.getElementById("outputArea").innerHTML = "";

    // Hide the file mode dividers for the cipher mode dropdown
    document.getElementById("fileModeDivider1").style.display = "none";
    document.getElementById("fileModeDivider2").style.display = "none";
    // Hide Base64 mode
    document.getElementById("Base64ModeLabel").style.display = "none";

    // Hide file input area
    document.getElementById("fileInputArea").style.display = "none";
    document.getElementById("fileUploadedText").style.display = "none";

    document.getElementById("timeTakenString").innerHTML = "";
    document.getElementById("outputFileArea").style.display = "none";
    toggleDownload("", "");  // Remove download functionality
    setClassicMode(); // Default back to classic mode
}

function setFileOption() {
    document.getElementById("activeDataFormat").innerHTML = "FILES &#x25BC;";
    document.getElementById("dataFormatInput").setAttribute("value", "Files");
    // Set output button to a download button
    document.getElementById("outputBtn").classList.remove("copy");
    document.getElementById("outputBtn").innerHTML = "Download File";
    // Show mode area, but hide input/output text boxes
    document.getElementById("modeArea").style.display = "block";
    document.getElementById("inputArea").style.display = "none";
    document.getElementById("outputArea").style.display = "none";
    // Show the file mode dividers for the cipher mode dropdown
    document.getElementById("fileModeDivider1").style.display = "block";
    document.getElementById("fileModeDivider2").style.display = "block";
    // Show Base64 mode
    document.getElementById("Base64ModeLabel").style.display = "block";

    // Show file input area and hide the uploaded file text
    document.getElementById("fileInputArea").style.display = "block";
    document.getElementById("fileUploadedText").style.display = "none";
    // By default, the mode is classic, so only allow text files
    document.getElementById("uploadText").innerHTML = "Upload a file (.TXT)";
    document.getElementById("fileInput").setAttribute("accept", ".txt");
    document.getElementById("timeTakenString").innerHTML = "";
    document.getElementById("outputFileArea").innerHTML = "";
    toggleDownload("", "");  // Remove download functionality
    setClassicMode();  // Default back to classic mode
}

function setImageOption() {
    document.getElementById("activeDataFormat").innerHTML = "IMAGES &#x25BC;";
    document.getElementById("dataFormatInput").setAttribute("value", "Images");
    // Set output button to a download button
    document.getElementById("outputBtn").classList.remove("copy");
    document.getElementById("outputBtn").innerHTML = "Download Image";
    // Hide mode area and input/output text boxes
    document.getElementById("modeArea").style.display = "none";
    document.getElementById("inputArea").style.display = "none";
    document.getElementById("outputArea").style.display = "none";
    // Show file input area and hide the uploaded image text
    document.getElementById("fileInputArea").style.display = "block";
    document.getElementById("fileUploadedText").style.display = "none";

    document.getElementById("uploadText").innerHTML = "Upload an image (.PNG or .JPG)";
    document.getElementById("fileInput").setAttribute("accept", ".png,.jpg");
    document.getElementById("timeTakenString").innerHTML = "";
    document.getElementById("outputFileArea").innerHTML = "";
    toggleDownload("", "");  // Remove download functionality
    setClassicMode(); // Default back to classic mode
}


// Set cipher dropdown options
function showCipherDropdown() {document.getElementById("cipherDropdown").classList.toggle("show");}
function setCaesarOption() {
    document.getElementById("activeCipher").innerHTML = "Caesar Cipher &#x25BC;";
    document.getElementById("cipherInput").setAttribute("value", "Caesar Cipher");
    // Hide Triple DES keys
    document.getElementById("tDESKeys").style.display = "none";
    document.getElementById("ASCIIModeLabel").style.display = "block";
    // Set the number of rows of the input/output text boxes to the minimum
    document.getElementById("inputArea").rows = "8";
    document.getElementById("outputArea").rows = "8";
    document.getElementById("fileInputArea").style.padding = "60px 0";
}

function setVigenereOption() {
    document.getElementById("activeCipher").innerHTML = "Vigenere Cipher &#x25BC;";
    document.getElementById("cipherInput").setAttribute("value", "Vigenere Cipher");
    // Hide Triple DES keys
    document.getElementById("tDESKeys").style.display = "none";
    document.getElementById("ASCIIModeLabel").style.display = "block";
    // Set the number of rows of the input/output text boxes to the minimum
    document.getElementById("inputArea").rows = "8";
    document.getElementById("outputArea").rows = "8";
    document.getElementById("fileInputArea").style.padding = "60px 0";
}

function setDESOption() {
    document.getElementById("activeCipher").innerHTML = "DES &#x25BC;";
    document.getElementById("cipherInput").setAttribute("value", "DES Cipher");
    // Hide Triple DES keys
    document.getElementById("tDESKeys").style.display = "none";
    document.getElementById("ASCIIModeLabel").style.display = "none";
    // Set the number of rows of the input/output text boxes to the minimum
    document.getElementById("inputArea").rows = "8";
    document.getElementById("outputArea").rows = "8";
    document.getElementById("fileInputArea").style.padding = "60px 0";

    // Set default mode to classic
    setClassicMode();
}

function setTDESOption() {
    document.getElementById("activeCipher").innerHTML = "Triple DES &#x25BC;";
    document.getElementById("cipherInput").setAttribute("value", "Triple DES Cipher");
    // Hide Triple DES keys
    document.getElementById("tDESKeys").style.display = "block";
    document.getElementById("ASCIIModeLabel").style.display = "none";
    // Set the number of rows of the input/output text boxes to the maximum
    document.getElementById("inputArea").rows = "15";
    document.getElementById("outputArea").rows = "15";
    document.getElementById("fileInputArea").style.padding = "150px 0";

    // Set default mode to classic
    setClassicMode();
}

function setAESOption() {
    document.getElementById("activeCipher").innerHTML = "AES &#x25BC;";
    document.getElementById("cipherInput").setAttribute("value", "AES Cipher");
    // Hide Triple DES keys
    document.getElementById("tDESKeys").style.display = "none";
    document.getElementById("ASCIIModeLabel").style.display = "none";
    // Set the number of rows of the input/output text boxes to the minimum
    document.getElementById("inputArea").rows = "8";
    document.getElementById("outputArea").rows = "8";
    document.getElementById("fileInputArea").style.padding = "60px 0";

    // Set default mode to classic
    setClassicMode();
}

function setRC4Option() {
    document.getElementById("activeCipher").innerHTML = "RC4 &#x25BC;";
    document.getElementById("cipherInput").setAttribute("value", "RC4 Cipher");
    // Hide Triple DES keys
    document.getElementById("tDESKeys").style.display = "none";
    document.getElementById("ASCIIModeLabel").style.display = "none";
    // Set the number of rows of the input/output text boxes to the minimum
    document.getElementById("inputArea").rows = "8";
    document.getElementById("outputArea").rows = "8";
    document.getElementById("fileInputArea").style.padding = "60px 0";

    // Set default mode to classic
    setClassicMode();
}


// Set Cipher mode dropwdown
function showCipherModeDropdown() {document.getElementById("cipherModeDropdown").classList.toggle("show");}
function setClassicMode() {
    document.getElementById("activeCipherMode").innerHTML = "Classic &#x25BC;";
    document.getElementById("cipherModeInput").setAttribute("value", "Classic");
    // This mode only supports text files
    if (document.getElementById("dataFormatInput").value == "Files") {
        document.getElementById("uploadText").innerHTML = "Upload a file (.TXT)";
        document.getElementById("fileInput").setAttribute("accept", ".txt");
    }
}
function setASCIIMode() {
    document.getElementById("activeCipherMode").innerHTML = "ASCII &#x25BC;";
    document.getElementById("cipherModeInput").setAttribute("value", "ASCII");
    // This mode only supports text files
    if (document.getElementById("dataFormatInput").value == "Files") {
        document.getElementById("uploadText").innerHTML = "Upload a file (.TXT)";
        document.getElementById("fileInput").setAttribute("accept", ".txt");
    }
}
function setBase64Mode() {
    document.getElementById("activeCipherMode").innerHTML = "Base 64 &#x25BC;";
    document.getElementById("cipherModeInput").setAttribute("value", "Base64");
    // Base64 allows any file type
    document.getElementById("uploadText").innerHTML = "Upload a file (any file type)";
    document.getElementById("fileInput").removeAttribute("accept");

}

function checkInputValidation() {
    // Check input text box is not empty
    if (document.getElementById("inputArea").value == "" &&
        document.getElementById("dataFormatInput").value == "Messages") {return false;}

    // Check first key is not empty
    if (document.getElementById("keyInput").value == "") {return false;}

    // Check if length of key is less than 8
    if (document.getElementById("keyInput").value.length < 8) {
        document.getElementById("keyArea").classList.add("key-error");
        document.getElementById("key1Error").innerHTML = "ERROR: Key must be at least 8 characters long";
        document.getElementById("key1Error").style.display = "block";
        return false;
    } else {
        document.getElementById("keyArea").classList.remove("key-error");
        document.getElementById("key1Error").style.display = "none";
    }

    // Check validation for the extra keys in Triple DES
    if (document.getElementById("cipherInput").value == "Triple DES Cipher") {
        if (document.getElementById("keyInput2").value == "") {return false;}
        if (document.getElementById("keyInput2").value.length < 8) {
            document.getElementById("keyArea2").classList.add("key-error");
            document.getElementById("key2Error").innerHTML = "ERROR: Key 2 must be at least 8 characters long";
            document.getElementById("key2Error").style.display = "block";
            return false;
        } else {
            document.getElementById("keyArea2").classList.remove("key-error");
            document.getElementById("key2Error").style.display = "none";
        }

        if (document.getElementById("keyInput3").value == "") {return false;}
        if (document.getElementById("keyInput3").value.length < 8) {
            document.getElementById("keyArea3").classList.add("key-error");
            document.getElementById("key3Error").innerHTML = "ERROR: Key 3 must be at least 8 characters long";
            document.getElementById("key3Error").style.display = "block";
            return false;
        } else {
            document.getElementById("keyArea3").classList.remove("key-error");
            document.getElementById("key3Error").style.display = "none";
        }
    }

    // Check if the key is only alphabetic using regex for Vigenere Cipher
    if (document.getElementById("cipherInput").value == "Vigenere Cipher" &&
        document.getElementById("cipherModeInput").value == "Classic" &&
        !document.getElementById("keyInput").value.match(/^[A-Za-z]+$/)) {

        document.getElementById("keyArea").classList.add("key-error");
        document.getElementById("key1Error").innerHTML = "ERROR: Key must not contain any ASCII characters using this mode";
        document.getElementById("key1Error").style.display = "block";
        return false;
    }

    // All validation tests passed
    return true;
}

// Set encrypt/decrypt modes
function startEncrypt() {
    // Check all input validations are passed before submitting
    if (checkInputValidation()) {
        // Check file size validation
        if (document.getElementById("dataFormatInput").value == "Files" ||
            document.getElementById("dataFormatInput").value == "Images") {
            var filename = document.getElementById("fileInput").files[0].name;
            var filesize = document.getElementById("fileInput").files[0].size;

            // Check file size is not larger than 1MB when encrypting
            if (filesize > 1000000) {
                document.getElementById("fileUploadedText").style.color = "#F44336";
                if (document.getElementById("dataFormatInput").value == "Images") {
                    document.getElementById("fileUploadedText").innerHTML = "Image too large! Please select an image less than 1MB for encryption.";
                } else {
                    document.getElementById("fileUploadedText").innerHTML = "File too large! Please select a file less than 1MB for encryption.";
                }
                return 0;  // Don't proceed to encrypt
            } else {

            }
        }

        // Proceed to encryption by submitting form
        document.getElementById("processInput").setAttribute("value", "encrypt");
        document.getElementById("padlockForm").submit();
    }
}
function startDecrypt() {
    if (checkInputValidation()) {
        // NOTE: For files and images, they can be any size when decrypting

        if (document.getElementById("dataFormatInput").value == "Files" ||
            document.getElementById("dataFormatInput").value == "Images") {
            // Set the file uploaded text

            var filename = document.getElementById("fileInput").files[0].name;
            document.getElementById("fileUploadedText").style.color = "#FBB300";
            if (document.getElementById("dataFormatInput").value == "Images") {
                document.getElementById("fileUploadedText").innerHTML = "Image uploaded: " + filename;
            } else {
                document.getElementById("fileUploadedText").innerHTML = "File uploaded: " + filename;
            }
        }

        // Proceed to decryption by submitting form
        document.getElementById("processInput").setAttribute("value", "decrypt");
        document.getElementById("padlockForm").submit();
    }
}


function copyOutput() {
    // Copy output message
    if (document.getElementById("outputBtn").classList.contains("copy")) {
        document.getElementById("outputArea").disabled = false;
        document.getElementById("outputArea").select();
        document.execCommand('copy');
        document.getElementById("outputArea").disabled = true;
    }
}


function uploadFile() {
    // Click the file input
    document.getElementById("fileInput").click();
    document.getElementById("fileUploadedText").style.display = "block";

    // When a user has selected a file, update the file input area
    $('#fileInput').change(function(e) {
        updateFileInputArea();
    });
}

function updateFileInputArea() {
    // Set the file uploaded text after user is done with selecting a file
    var fileUploadedText = document.getElementById("fileUploadedText");
    var filename = document.getElementById("fileInput").files[0].name;
    var extension = filename.split('.').pop().toLowerCase();

    // Check file uploaded is of a valid type
    if (document.getElementById("dataFormatInput").value == "Files") {
        // File must be a text file if Base64 is not chosen
        if (document.getElementById("cipherModeInput").value != "Base64" &&
        extension != "txt") {
            fileUploadedText.style.color = "#F44336";
            fileUploadedText.innerHTML = "File uploaded is not a text file!";
            return 0;
        }
    }

    // Check image uploaded is of a valid type
    else {
        if (extension != "png" && extension != "jpg") {
            fileUploadedText.style.color = "#F44336";
            fileUploadedText.innerHTML = "Image uploaded is not a PNG or JPG!";
            return 0;
        }
    }

    fileUploadedText.style.color = "#FBB300";
    if (document.getElementById("dataFormatInput").value == "Images") {
        fileUploadedText.innerHTML = "Image uploaded: " + filename;
    } else {
        fileUploadedText.innerHTML = "File uploaded: " + filename;
    }
}

function toggleDownload(filepath, filename) {
    outputBtn = document.getElementById("outputBtn");
    if (filename !== "") {
        outputBtn.setAttribute("href", filepath);
        outputBtn.setAttribute("download", filename);

    }
    else {
        outputBtn.removeAttribute("download");
        outputBtn.removeAttribute("href");
    }
}
