import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import re
import binascii
from cryptography.hazmat.primitives import hashes
import AES
import certificate



private_key, public_key = certificate.key_generation()

class EncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Encryption and Signing App")

        # UI Components
        self.label = tk.Label(master, text="File Path:")
        self.label.grid(row=0, column=0, sticky='w')

        self.file_path_entry = tk.Entry(master, width=50)
        self.file_path_entry.grid(row=0, column=1, columnspan=2, pady=5, padx=10, sticky='w')

        self.browse_button = tk.Button(master, text="Browse", command=self.browse_file)
        self.browse_button.grid(row=0, column=3, pady=5, padx=10, sticky='w')

        self.encryption_method_label = tk.Label(master, text="Encryption Method:")
        self.encryption_method_label.grid(row=1, column=0, sticky='w')

        # Dropdown menu for encryption method
        self.encryption_methods = ["AES", "RSA"]
        self.selected_encryption_method = tk.StringVar()
        self.selected_encryption_method.set("Encryption Method")  # Default placeholder text
        self.encryption_method_menu = tk.OptionMenu(master, self.selected_encryption_method, *self.encryption_methods, command=self.update_components)
        self.encryption_method_menu.grid(row=1, column=1, pady=5, padx=10, sticky='w')

        self.key_label = tk.Label(master, text="Key (32 digits in hexadecimal):")
        self.key_label.grid(row=2, column=0, sticky='w')
        self.key_label.grid_forget()

        self.key_entry = tk.Entry(master, width=50)
        self.key_entry.grid(row=2, column=1, columnspan=2, pady=5, padx=10, sticky='w')
        self.key_entry.grid_forget()  # Initially hide the key entry field

        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt_file)
        self.encrypt_button.grid(row=3, column=1, pady=5, padx=10, sticky='w')
        self.encrypt_button.grid_forget()  # Initially hide the encrypt button

        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt_file)
        self.decrypt_button.grid(row=3, column=2, pady=5, padx=10, sticky='w')
        self.decrypt_button.grid_forget()  # Initially hide the decrypt button

        self.encrypt_sign_button = tk.Button(master, text="Generate Signature", command=self.encrypt_sign_file)
        self.encrypt_sign_button.grid(row=3, column=1, pady=5, padx=10, sticky='w')
        self.encrypt_sign_button.grid_forget()  # Initially hide the encrypt sign button

        self.decrypt_verify_button = tk.Button(master, text="Verify Certificate", command=self.decrypt_verify_file)
        self.decrypt_verify_button.grid(row=3, column=2, pady=5, padx=10, sticky='w')
        self.decrypt_verify_button.grid_forget()  # Initially hide the decrypt verify button

    def update_components(self, *args):
        # Function to update components based on the selected encryption method
        encryption_method = self.selected_encryption_method.get()

        # Hide all components initially
        # self.key_label.grid_forget()
        self.key_entry.grid_forget()
        self.encrypt_button.grid_forget()
        self.decrypt_button.grid_forget()
        self.encrypt_sign_button.grid_forget()
        self.decrypt_verify_button.grid_forget()

        # Show relevant components based on the selected encryption method
        if encryption_method == "AES":
            self.key_label.grid(row=2, column=0, sticky='w')
            self.key_entry.grid(row=2, column=1, columnspan=2, pady=5, padx=10, sticky='w')
            self.encrypt_button.grid(row=3, column=1, pady=5, padx=10, sticky='w')
            self.decrypt_button.grid(row=3, column=2, pady=5, padx=10, sticky='w')
        elif encryption_method == "RSA":
            self.encrypt_sign_button.grid(row=3, column=1, pady=5, padx=10, sticky='w')
            self.decrypt_verify_button.grid(row=3, column=2, pady=5, padx=10, sticky='w')

    def validate_input(self, value):
        # Check if the input is a valid hexadecimal string of length 32
        return re.match(r'^[0-9a-fA-F]{32}$', value) is not None

    def browse_file(self):
        file_types = [("Supported files", ("*.txt", "*.cert"))]
        file_path = filedialog.askopenfilename(filetypes=file_types)
        if file_path:
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, file_path)

    def get_key(self):
        password = self.key_entry.get().encode('utf-8')
        if not self.validate_input(password.decode('utf-8')):
            tk.messagebox.showerror("Error", "Invalid key. Please enter a valid 32-digit hexadecimal key.")
            return None

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            salt=b'salt_123',
            iterations=100000,
            length=32,
            backend=default_backend()
        )
        key = kdf.derive(password)
        hex_key = binascii.hexlify(key).decode('ascii')
        return hex_key



    def encrypt_file(self):
        file_path = self.file_path_entry.get()
        key = self.get_key()
        AES.encrypt_file(file_path, key)

    def decrypt_file(self):
        file_path = self.file_path_entry.get()
        key = self.get_key()
        AES.decrypt_file(file_path, key)

    def encrypt_sign_file(self):
        file_path = self.file_path_entry.get()
        certificate.generate_signature_and_certificate(file_path, private_key)

    def decrypt_verify_file(self):
        file_path = self.file_path_entry.get()
        certificate.verify_certificate(private_key, public_key, file_path)


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
