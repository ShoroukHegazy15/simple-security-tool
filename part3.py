import tkinter as tk
from tkinter import filedialog
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii
import base64

class AESCipher:
    def __init__(self, key):
        self.key = binascii.unhexlify(key)

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_ECB)
        if len(data) % 2 != 0:
            data = '0' + data
        padded_data = pad(binascii.unhexlify(data), AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        return binascii.hexlify(encrypted_data).decode('ascii')
    
    def decrypt(self, encrypted_data):
        cipher = AES.new(self.key, AES.MODE_ECB)
        decrypted_data = cipher.decrypt(binascii.unhexlify(encrypted_data))
        unpadded_data = unpad(decrypted_data, AES.block_size)
        return binascii.hexlify(unpadded_data).decode('ascii')



def key_generation_a():
    private_key_a = RSA.generate(2048)
    public_key_a = private_key_a.publickey()

    return private_key_a, public_key_a 


# private_key_a, public_key_a = key_generation_a()

def generate_signature_and_certificate(file_path, private_key_a):

    # Read content from a file
    with open(file_path, "rb") as file:
        original_content = file.read()

    # Signing
    hash_object = SHA256.new(original_content)
    signature = pkcs1_15.new(private_key_a).sign(hash_object)

    # Combine original content and signature
    certificate_content = original_content + signature

    return certificate_content
    # Save as a certificate file
    # with open("signed_file.cert",'wb') as file:
    #     file.write(certificate_content)
    
def encrypt_file(path , key, private_key_a):
    # with open(path, 'r') as file:
    #     lines = file.read()
    certificate_content = generate_signature_and_certificate(path, private_key_a)
    hex_representation = binascii.hexlify(certificate_content).decode('ascii')
    cypher = AESCipher(key)
    final_encrypted = base64.b64encode(bytes.fromhex(cypher.encrypt(hex_representation))).decode('utf-8')
    
    with open("confidintialencrypted.txt",'w') as file:
        file.write(final_encrypted)


def verify_certificate(private_key_a, public_key_a, certificate_file_path, key):
    # Read certificate content from a file
    decrypted_bytes = decrypt_file(certificate_file_path, key)
    received_content = decrypted_bytes[:-private_key_a.size_in_bytes()]
    received_signature = decrypted_bytes[-private_key_a.size_in_bytes():]
    # Verification
    hash_object = SHA256.new(received_content)

    try:
        pkcs1_15.new(public_key_a).verify(hash_object, received_signature)
        print("Signature verification successful!")
        
        with open("verifieddecrypted.txt", 'wb') as file:
            file.write(received_content)
            
    except (ValueError, TypeError):
        print("Signature verification failed.")


def decrypt_file(path, key):
    with open(path, 'rb') as file:
        lines = file.read()
    decoded_bytes = base64.b64decode(lines)
    hex_representation = binascii.hexlify(decoded_bytes).decode('ascii')
    cypher = AESCipher(key)
    decrypted_bytes = binascii.unhexlify(cypher.decrypt(hex_representation))

    # with open("originaldecrypted.txt", 'w') as file:
    #     file.write(decrypted)
    return decrypted_bytes


# encrypt_file('text.txt' , "000102030405060708090a0b0c0d0e0f")
# verify_certificate(private_key_a, public_key_a, 'final_encrypted.txt', "000102030405060708090a0b0c0d0e0f")