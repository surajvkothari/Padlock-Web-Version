/*
Padlock - JavaScript
Author: Suraj Kothari
*/
// Initialises the site upon refresh
function initialiseSite() {
    if (document.getElementById("dataFormatInput").value == "Messages") {
        document.getElementById("outputFileArea").style.display = "none";
        document.getElementById("outputBtn").innerHTML = "Copy message";
        document.getElementById("outputBtn").classList.add("copy");
        // Hide image
        document.getElementById("outputImage").style.display = "none";
    }

    if (document.getElementById("dataFormatInput").value == "Files") {
        document.getElementById("fileInputArea").style.display = "block";
        document.getElementById("inputArea").style.display = "none";
        document.getElementById("outputArea").style.display = "none";
        document.getElementById("uploadText").innerHTML = "Upload a file (any file type)";
        document.getElementById("outputBtn").innerHTML = "Download File";
        // Hide image
        document.getElementById("outputImage").style.display = "none";
    } else if (document.getElementById("dataFormatInput").value == "Images") {
        document.getElementById("fileInputArea").style.display = "block";
        document.getElementById("inputArea").style.display = "none";
        document.getElementById("outputArea").style.display = "none";
        document.getElementById("uploadText").innerHTML = "Upload an image (.PNG or .JPG)";
        document.getElementById("outputBtn").innerHTML = "Download Image";

        // Display image
        document.getElementById("outputImage").style.display = "block";
    }

    // Hide the extra keys if not triple des selected
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
    document.getElementById("outputBtn").classList.add("copy");
    document.getElementById("outputBtn").value = "Copy Message";
    document.getElementById("modeArea").style.display = "block";
    document.getElementById("Base64ModeLabel").style.display = "none";
    document.getElementById("fileModeDivider1").style.display = "none";
    document.getElementById("fileModeDivider2").style.display = "none";
    document.getElementById("inputArea").style.display = "block";
    document.getElementById("fileInputArea").style.display = "none";
    document.getElementById("outputArea").style.display = "block";
    document.getElementById("dataFormatInput").setAttribute("value", "Messages");
    document.getElementById("inputArea").innerHTML = "";
    document.getElementById("outputArea").innerHTML = "";
    document.getElementById("outputFileArea").style.display = "none";
}
function setFileOption() {
    document.getElementById("activeDataFormat").innerHTML = "FILES &#x25BC;";
    document.getElementById("outputBtn").classList.remove("copy");
    document.getElementById("outputBtn").innerHTML = "Download File";
    document.getElementById("modeArea").style.display = "block";
    document.getElementById("Base64ModeLabel").style.display = "block";
    document.getElementById("fileModeDivider1").style.display = "block";
    document.getElementById("fileModeDivider2").style.display = "block";
    document.getElementById("inputArea").style.display = "none";
    document.getElementById("fileInputArea").style.display = "block";
    document.getElementById("fileInput").removeAttribute("accept");
    document.getElementById("fileUploadedText").style.display = "none";
    document.getElementById("outputArea").style.display = "none";
    document.getElementById("dataFormatInput").setAttribute("value", "Files");
    document.getElementById("uploadText").innerHTML = "Upload a file (any file type)";
    document.getElementById("timeTakenString").innerHTML = "";
    document.getElementById("outputFileArea").innerHTML = "";
    // Add download attribute to button

}
function setImageOption() {
    document.getElementById("activeDataFormat").innerHTML = "IMAGES &#x25BC;";
    document.getElementById("outputBtn").classList.remove("copy");
    document.getElementById("outputBtn").innerHTML = "Download Image";
    document.getElementById("modeArea").style.display = "none";
    document.getElementById("inputArea").style.display = "none";
    document.getElementById("fileInputArea").style.display = "block";
    document.getElementById("fileInput").setAttribute("accept", ".png,.jpg");
    document.getElementById("fileUploadedText").style.display = "none";
    document.getElementById("outputArea").style.display = "none";
    document.getElementById("dataFormatInput").setAttribute("value", "Images");
    document.getElementById("uploadText").innerHTML = "Upload an image (.PNG or .JPG)";
    document.getElementById("timeTakenString").innerHTML = "";
    document.getElementById("outputFileArea").innerHTML = "";
}

// Set cipher dropdown options
function showCipherDropdown() {document.getElementById("cipherDropdown").classList.toggle("show");}
function setCaesarOption() {
    document.getElementById("activeCipher").innerHTML = "Caesar Cipher &#x25BC;";
    // Hide Triple DES keys
    document.getElementById("tDESKeys").style.display = "none";
    document.getElementById("ASCIIModeLabel").style.display = "block";
    document.getElementById("inputArea").rows = "8";
    document.getElementById("fileInputArea").style.padding = "60px 0";
    document.getElementById("outputArea").rows = "8";
    document.getElementById("cipherInput").setAttribute("value", "Caesar Cipher");
}
function setVigenereOption() {
    document.getElementById("activeCipher").innerHTML = "Vigenere Cipher &#x25BC;";
    // Hide Triple DES keys
    document.getElementById("tDESKeys").style.display = "none";
    document.getElementById("ASCIIModeLabel").style.display = "block";
    document.getElementById("inputArea").rows = "8";
    document.getElementById("fileInputArea").style.padding = "60px 0";
    document.getElementById("outputArea").rows = "8";
    document.getElementById("cipherInput").setAttribute("value", "Vigenere Cipher");
}
function setDESOption() {
    document.getElementById("activeCipher").innerHTML = "DES &#x25BC;";
    // Hide Triple DES keys
    document.getElementById("tDESKeys").style.display = "none";
    document.getElementById("ASCIIModeLabel").style.display = "none";
    document.getElementById("inputArea").rows = "8";
    document.getElementById("fileInputArea").style.padding = "60px 0";
    document.getElementById("outputArea").rows = "8";
    document.getElementById("cipherInput").setAttribute("value", "DES Cipher");
    // Remove ASCII mode
    setClassicMode();
}
function setTDESOption() {
    document.getElementById("activeCipher").innerHTML = "Triple DES &#x25BC;";
    // Hide Triple DES keys
    document.getElementById("tDESKeys").style.display = "block";
    document.getElementById("ASCIIModeLabel").style.display = "none";
    document.getElementById("inputArea").rows = "15";
    document.getElementById("fileInputArea").style.padding = "150px 0";
    document.getElementById("outputArea").rows = "15";
    document.getElementById("cipherInput").setAttribute("value", "Triple DES Cipher");
    // Remove ASCII mode
    setClassicMode();
}
function setAESOption() {
    document.getElementById("activeCipher").innerHTML = "AES &#x25BC;";
    // Hide Triple DES keys
    document.getElementById("tDESKeys").style.display = "none";
    document.getElementById("ASCIIModeLabel").style.display = "none";
    document.getElementById("inputArea").rows = "8";
    document.getElementById("fileInputArea").style.padding = "60px 0";
    document.getElementById("outputArea").rows = "8";
    document.getElementById("cipherInput").setAttribute("value", "AES Cipher");
    // Remove ASCII mode
    setClassicMode();
}
function setRC4Option() {
    document.getElementById("activeCipher").innerHTML = "RC4 &#x25BC;";
    // Hide Triple DES keys
    document.getElementById("tDESKeys").style.display = "none";
    document.getElementById("ASCIIModeLabel").style.display = "none";
    document.getElementById("inputArea").rows = "8";
    document.getElementById("fileInputArea").style.padding = "60px 0";
    document.getElementById("outputArea").rows = "8";
    document.getElementById("cipherInput").setAttribute("value", "RC4 Cipher");
    // Remove ASCII mode
    setClassicMode();
}

// Set Cipher mode dropwdown
function showCipherModeDropdown() {document.getElementById("cipherModeDropdown").classList.toggle("show");}
function setClassicMode() {
    document.getElementById("activeCipherMode").innerHTML = "Classic &#x25BC;";
    document.getElementById("cipherModeInput").setAttribute("value", "Classic");
}
function setASCIIMode() {
    document.getElementById("activeCipherMode").innerHTML = "ASCII &#x25BC;";
    document.getElementById("cipherModeInput").setAttribute("value", "ASCII");
}
function setBase64Mode() {
    document.getElementById("activeCipherMode").innerHTML = "Base 64 &#x25BC;";
    document.getElementById("cipherModeInput").setAttribute("value", "Base64");
}


// Close the dropdown if the user clicks outside of it
// Reference: https://www.w3schools.com/howto/howto_js_dropdown.asp
window.onclick = function(event) {
  if (!event.target.matches('.dropdown-btn')) {
    var dropdowns = document.getElementsByClassName("dropdown-body");
    var i;
    for (i = 0; i < dropdowns.length; i++) {
      var openDropdown = dropdowns[i];
      if (openDropdown.classList.contains('show')) {
        openDropdown.classList.remove('show');
      }
    }
  }
}

function checkInputValidation() {
    // Check input text box
    if (document.getElementById("inputArea").value == "" &&
        document.getElementById("dataFormatInput").value == "Messages") {return false;}

    // Check first key
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

    // Check Triple DES extra keys validation
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

    // Check if key is alphabetic using regex
    if (document.getElementById("cipherInput").value == "Vigenere Cipher" &&
        document.getElementById("cipherModeInput").value == "Classic" &&
        !document.getElementById("keyInput").value.match(/^[A-Za-z]+$/)) {

        document.getElementById("keyArea").classList.add("key-error");
        document.getElementById("key1Error").innerHTML = "ERROR: Key must not contain any ASCII characters using this mode";
        document.getElementById("key1Error").style.display = "block";
        return false;
    }

    return true;
}

// Set encrypt/decrypt modes
function startEncrypt() {
    // Checks input validation before submitting
    if (checkInputValidation()) {
        // Check input validation for files and images
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
        // NOTE: For files and images, they can be any size if decrypting

        if (document.getElementById("dataFormatInput").value == "Files" ||
            document.getElementById("dataFormatInput").value == "Images") {
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
    // Clicks the file import form
    document.getElementById("fileInput").click();
    // Once user has chosen the file, change the input for flask
    $('#fileInput').change(function(e) {
        var filename = e.target.files[0].name;
        // var filesize = e.target.files[0].size;
        document.getElementById("fileUploadedText").style.display = "block";

        document.getElementById("fileUploadedText").style.color = "#FBB300";
        if (document.getElementById("dataFormatInput").value == "Images") {
            document.getElementById("fileUploadedText").innerHTML = "Image uploaded: " + filename;
        } else {
            document.getElementById("fileUploadedText").innerHTML = "File uploaded: " + filename;
        }
    });
}
