import tkinter as tk
from tkinter import filedialog
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


def key_generation():
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()

    return private_key, public_key 


def generate_signature_and_certificate(file_path, private_key):

    # Read content from a file
    with open(file_path, "rb") as file:
        original_content = file.read()

    # Signing
    hash_object = SHA256.new(original_content)
    signature = pkcs1_15.new(private_key).sign(hash_object)

    # Combine original content and signature
    certificate_content = original_content + signature

    # Save as a certificate file
    with open("certificatesigned.cert",'wb') as file:
        file.write(certificate_content)
    # with open(certificate_file_path, "wb") as certificate_file:
    #     certificate_file.write()

    # print(f"Signature and certificate file saved successfully at {certificate_file_path}.")

def verify_certificate(private_key, public_key, certificate_file_path):
    # Read certificate content from a file
    with open(certificate_file_path, "rb") as certificate_file:
        certificate_content = certificate_file.read()
        received_content = certificate_content[:-private_key.size_in_bytes()]
        received_signature = certificate_content[-private_key.size_in_bytes():]

    # Verification
    hash_object = SHA256.new(received_content)

    try:
        pkcs1_15.new(public_key).verify(hash_object, received_signature)
        print("Signature verification successful!")

        # Save the verified content to a new file
        with open("verified.txt",'wb') as file:
            file.write(received_content)
        
    except (ValueError, TypeError):
        print("Signature verification failed.")

# Example usage:
# file_path = "test1.txt"
# private_key, public_key = key_generation()

# generate_signature_and_certificate(file_path, private_key)

# verify_certificate(private_key, public_key, "certificate_file.cert")