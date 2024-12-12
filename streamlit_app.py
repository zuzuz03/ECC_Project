import streamlit as st
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
import socket
import threading
import os

# Constants for server communication
HOST = '127.0.0.1'
PORT = 65432

# Encryption utility functions
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_key)
    return derived_key

def encrypt_message(key, plaintext):
    # Generate a random IV
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Pad plaintext to be block-aligned
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext

def decrypt_message(key, ciphertext):
    # Extract IV and actual ciphertext
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt and unpad the ciphertext
    padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode()

# Server to handle encrypted message transmission
def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        conn, addr = server_socket.accept()
        with conn:
            st.session_state["received_encrypted_message"] = conn.recv(1024)

def send_message(encrypted_message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, PORT))
        client_socket.sendall(encrypted_message)

# Streamlit application
def main():
    st.title("Message Encryption using Elliptic Curve Cryptography")

    mode = st.radio("Are you a sender or receiver?", ("Sender", "Receiver"))

    if mode == "Sender":
        st.header("Sender Mode")

        # Generate sender keys
        sender_private_key, sender_public_key = generate_keys()
        st.write("Sender's ECC key pair generated.")

        # Display sender's public key
        sender_public_pem = sender_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        st.text_area("Sender Public Key (share this):", sender_public_pem.decode(), height=100)

        peer_public_key_pem = st.text_area("Enter Receiver's Public Key:")
        if st.button("Set Receiver Public Key"):
            peer_public_key = serialization.load_pem_public_key(peer_public_key_pem.encode())

            # Derive shared key
            shared_key = derive_shared_key(sender_private_key, peer_public_key)
            st.write("Shared key derived.")

            # Enter message for encryption
            message = st.text_input("Enter the message to encrypt:")
            if message:
                encrypted_message = encrypt_message(shared_key, message)
                st.write("Message encrypted.")

                # Send the encrypted message to receiver
                send_message(encrypted_message)
                st.write("Encrypted message sent.")

    elif mode == "Receiver":
        st.header("Receiver Mode")

        # Generate receiver keys
        receiver_private_key, receiver_public_key = generate_keys()
        st.write("Receiver's ECC key pair generated.")

        # Display receiver's public key
        receiver_public_pem = receiver_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        st.text_area("Receiver Public Key (share this):", receiver_public_pem.decode(), height=100)

        # Wait for encrypted message from sender
        if st.button("Start Server to Receive Message"):
            threading.Thread(target=start_server).start()

        if "received_encrypted_message" in st.session_state:
            encrypted_message = st.session_state["received_encrypted_message"]
            st.write("Encrypted message received:", base64.b64encode(encrypted_message).decode())

            peer_public_key_pem = st.text_area("Enter Sender's Public Key:")
            if st.button("Set Sender Public Key"):
                peer_public_key = serialization.load_pem_public_key(peer_public_key_pem.encode())

                # Derive shared key
                shared_key = derive_shared_key(receiver_private_key, peer_public_key)
                st.write("Shared key derived.")

                # Decrypt message
                decrypted_message = decrypt_message(shared_key, encrypted_message)
                st.write("Decrypted message:", decrypted_message)

if __name__ == "__main__":
    main()
