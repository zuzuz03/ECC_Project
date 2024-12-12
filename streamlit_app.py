# streamlit_app.py
import streamlit as st
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

# Helper functions
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_key(sender_private_key, receiver_public_key):
    shared_key = sender_private_key.exchange(ec.ECDH(), receiver_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"encryption key",
    ).derive(shared_key)
    return derived_key

def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_message(encrypted_message, key):
    data = base64.b64decode(encrypted_message)
    iv, ciphertext = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

# Streamlit interface
st.title("Message Encryption using ECC")

role = st.radio("Select your role", ("Sender", "Receiver"))

if role == "Sender":
    st.header("Sender's Side")

    if "sender_private_key" not in st.session_state:
        st.session_state.sender_private_key, st.session_state.sender_public_key = generate_keys()

    st.write("Your public key (share with receiver):")
    st.code(base64.b64encode(
        st.session_state.sender_public_key.public_bytes(
            encoding=ec.Encoding.PEM,
            format=ec.PublicFormat.SubjectPublicKeyInfo,
        )).decode())

    receiver_public_key_pem = st.text_area("Enter Receiver's Public Key")

    if st.button("Generate Shared Key"):
        try:
            receiver_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), base64.b64decode(receiver_public_key_pem.encode())
            )
            st.session_state.shared_key = derive_shared_key(
                st.session_state.sender_private_key, receiver_public_key
            )
            st.success("Shared key successfully derived!")
        except Exception as e:
            st.error(f"Error: {e}")

    message = st.text_input("Enter a message to encrypt")
    if st.button("Encrypt Message"):
        if "shared_key" in st.session_state:
            encrypted_message = encrypt_message(message, st.session_state.shared_key)
            st.session_state.encrypted_message = encrypted_message
            st.write("Encrypted Message:")
            st.code(encrypted_message)
        else:
            st.error("Generate the shared key first.")

elif role == "Receiver":
    st.header("Receiver's Side")

    if "receiver_private_key" not in st.session_state:
        st.session_state.receiver_private_key, st.session_state.receiver_public_key = generate_keys()

    st.write("Your public key (share with sender):")
    st.code(base64.b64encode(
        st.session_state.receiver_public_key.public_bytes(
            encoding=ec.Encoding.PEM,
            format=ec.PublicFormat.SubjectPublicKeyInfo,
        )).decode())

    sender_public_key_pem = st.text_area("Enter Sender's Public Key")

    if st.button("Generate Shared Key"):
        try:
            sender_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), base64.b64decode(sender_public_key_pem.encode())
            )
            st.session_state.shared_key = derive_shared_key(
                st.session_state.receiver_private_key, sender_public_key
            )
            st.success("Shared key successfully derived!")
        except Exception as e:
            st.error(f"Error: {e}")

    encrypted_message = st.text_area("Paste the encrypted message")
    if st.button("Decrypt Message"):
        if "shared_key" in st.session_state:
            try:
                decrypted_message = decrypt_message(encrypted_message, st.session_state.shared_key)
                st.write("Decrypted Message:")
                st.code(decrypted_message)
            except Exception as e:
                st.error(f"Error during decryption: {e}")
        else:
            st.error("Generate the shared key first.")
