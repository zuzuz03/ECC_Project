import streamlit as st
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
import socket
import threading
import time

# Server to facilitate key and message exchange
HOST = '127.0.0.1'  # Localhost
PORT = 65433
shared_data = {'encrypted_message': None, 'shared_key': None}

# Function for the server thread
def server_thread():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(1)
    conn, _ = server.accept()

    while True:
        data = conn.recv(1024).decode()
        if data.startswith("KEY:"):
            shared_data['shared_key'] = data[4:]
        elif data.startswith("MSG:"):
            shared_data['encrypted_message'] = data[4:]

    conn.close()
    server.close()

threading.Thread(target=server_thread, daemon=True).start()

# ECC Key generation
# ECC Key generation with persistence
def get_or_create_keys(role):
    if f"{role}_private_key" not in st.session_state:
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        st.session_state[f"{role}_private_key"] = private_key
        st.session_state[f"{role}_public_key"] = public_key
    return st.session_state[f"{role}_private_key"], st.session_state[f"{role}_public_key"]


# Encrypt using AES
def aes_encrypt(shared_key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(shared_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv, ciphertext

# Decrypt using AES
def aes_decrypt(shared_key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(shared_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

# Streamlit app logic
st.title("Message Encryption using Elliptic Curve Cryptography")

option = st.selectbox("Select your role:", ["Sender", "Receiver"])

if option == "Sender":
    st.header("Sender Section")

    sender_private_key, sender_public_key = get_or_create_keys("sender")
    sender_public_pem = sender_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    st.write("Generated Public Key:")
    st.code(sender_public_pem.decode())

    receiver_public_key_pem = st.text_area("Enter Receiver's Public Key:")

    if receiver_public_key_pem:
        receiver_public_key = serialization.load_pem_public_key(
            receiver_public_key_pem.encode()
        )

        shared_key = sender_private_key.exchange(ec.ECDH(), receiver_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake'
        ).derive(shared_key)

        message = st.text_input("Enter message to encrypt:")
        if message:
            iv, encrypted_message = aes_encrypt(derived_key, message)
            st.write("Encryption Steps:")
            st.write(f"1. Shared key derived using ECC: {base64.b64encode(shared_key).decode()}")
            st.write(f"2. AES encryption applied with IV: {base64.b64encode(iv).decode()}.")
            st.write(f"3. Encrypted Message: {base64.b64encode(encrypted_message).decode()}.")

            # Send to server
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                s.sendall(f"KEY:{base64.b64encode(derived_key).decode()}".encode())
                s.sendall(f"MSG:{base64.b64encode(iv + encrypted_message).decode()}".encode())

if option == "Receiver":
    st.header("Receiver Section")

    receiver_private_key, receiver_public_key = get_or_create_keys("receiver")
    receiver_public_pem = receiver_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    st.write("Generated Public Key:")
    st.code(receiver_public_pem.decode())

    sender_public_key_pem = st.text_area("Enter Sender's Public Key:")

    if sender_public_key_pem:
        sender_public_key = serialization.load_pem_public_key(
            sender_public_key_pem.encode()
        )

        st.write("Waiting for the encrypted message...")

        while not shared_data['shared_key'] or not shared_data['encrypted_message']:
            time.sleep(1)  # Wait for the server to update the shared data

        shared_key = base64.b64decode(shared_data['shared_key'])
        encrypted_data = base64.b64decode(shared_data['encrypted_message'])
        iv, ciphertext = encrypted_data[:16], encrypted_data[16:]

        st.write("Decryption Steps:")
        st.write(f"1. Shared key derived using ECC: {base64.b64encode(shared_key).decode()}.")
        st.write(f"2. Extracted IV: {base64.b64encode(iv).decode()}.")
        st.write(f"3. Ciphertext: {base64.b64encode(ciphertext).decode()}.")

        plaintext = aes_decrypt(shared_key, iv, ciphertext)
        st.write("Decrypted Message:")
        st.success(plaintext)
