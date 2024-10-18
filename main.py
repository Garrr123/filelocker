from fastapi import FastAPI, File, UploadFile, Form
from fastapi.responses import FileResponse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from fastapi.responses import StreamingResponse
import os
import io

app = FastAPI()

# Serve the index.html file
@app.get("/", response_class=FileResponse)
async def get_home():
    return "src/index.html"

@app.post("/encrypt/")
async def encrypt_file(password: str = Form(...), file: UploadFile = File(...)):
    # Read the uploaded .zip file content
    file_content = await file.read()

    # Create AES key from password
    key = password.encode('utf-8').ljust(32)[:32]

    # Generate an IV (Initialization Vector)
    iv = os.urandom(16)

    # Initialize AES cipher for encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Add padding to the file content
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_content) + padder.finalize()

    # Encrypt the .zip file content
    encrypted_content = encryptor.update(padded_data) + encryptor.finalize()

    # Combine IV and encrypted content
    final_content = iv + encrypted_content

    # Use BytesIO for in-memory file-like object
    encrypted_file = io.BytesIO(final_content)
    encrypted_file.seek(0)

    # Return the encrypted file using StreamingResponse
    return StreamingResponse(encrypted_file, media_type="application/octet-stream", 
                             headers={"Content-Disposition": f"attachment; filename=encrypted_{file.filename}"})


@app.post("/decrypt/")
async def decrypt_file(password: str = Form(...), file: UploadFile = File(...)):
    # Read the uploaded encrypted file content
    file_content = await file.read()

    # Extract IV and encrypted content
    iv = file_content[:16]
    encrypted_content = file_content[16:]

    # Create AES key from password
    key = password.encode('utf-8').ljust(32)[:32]

    # Initialize AES cipher for decryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the content
    decrypted_padded_content = decryptor.update(encrypted_content) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_content = unpadder.update(decrypted_padded_content) + unpadder.finalize()

    # Use BytesIO for in-memory file-like object
    decrypted_file = io.BytesIO(decrypted_content)
    decrypted_file.seek(0)

    # Return the decrypted file using StreamingResponse
    return StreamingResponse(decrypted_file, media_type="application/octet-stream", 
                             headers={"Content-Disposition": f"attachment; filename=decrypted_{file.filename}"})

