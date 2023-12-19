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

def encrypt_file(path , key):
    with open(path, 'r') as file:
        lines = file.read()
    hex_representation = binascii.hexlify(lines.encode('ascii')).decode('ascii')
    cypher = AESCipher(key)
    encrypted = base64.b64encode(bytes.fromhex(cypher.encrypt(hex_representation))).decode('utf-8')
    
    with open("encrypted.txt",'w') as file:
        file.write(encrypted)
        
def decrypt_file(path, key):
    with open(path, 'r') as file:
        lines = file.read()
    decoded_bytes = base64.b64decode(lines)
    hex_representation = binascii.hexlify(decoded_bytes).decode('ascii')
    cypher = AESCipher(key)
    decrypted = binascii.unhexlify(cypher.decrypt(hex_representation)).decode('utf-8')

    with open("originaldecrypted.txt", 'w') as file:
        file.write(decrypted)

    return decrypted



# decrypt_file("encrypted.txt" , '000102030405060708090a0b0c0d0e0f')