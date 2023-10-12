from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


class SecureEncryption:
    PRIVATE_KEY_PATH = 'private_key.pem'
    PUBLIC_KEY_PATH = 'public_key.pem'

    def __init__(self):
        self.backend = default_backend()
        if os.path.exists(self.PRIVATE_KEY_PATH) and os.path.exists(self.PUBLIC_KEY_PATH):
            with open(self.PRIVATE_KEY_PATH, 'rb') as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=self.backend
                )
            with open(self.PUBLIC_KEY_PATH, 'rb') as key_file:
                self.public_key = serialization.load_pem_public_key(key_file.read(), backend=self.backend)
        else:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=self.backend
            )
            self.public_key = self.private_key.public_key()
            # Save the keys to files
            with open(self.PRIVATE_KEY_PATH, 'wb') as key_file:
                key_file.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open(self.PUBLIC_KEY_PATH, 'wb') as key_file:
                key_file.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

    def serialize_public_key(self):
        pem = self.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
        return pem



    def encrypt(self, plaintext, public_key_pem):
        public_key = serialization.load_pem_public_key(public_key_pem, backend=self.backend)
        # Generate AES session key
        session_key = os.urandom(32)  # 256-bit session key
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        encrypted_session_key = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return (encrypted_session_key, nonce, ciphertext, encryptor.tag)
    
    def decrypt(self, encrypted_data):
        encrypted_session_key, nonce, ciphertext, tag = encrypted_data
        # Decrypt the session key with the private RSA key
        session_key = self.private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

def main():
    receiver = SecureEncryption()
    serialized_public_key = receiver.serialize_public_key()

    option = input("Do you want to (E)ncrypt or (D)ecrypt? ").lower()
    if option == 'e':
        # Sender encrypts the message
        message = input("Enter the message to encrypt: ")
        encrypted_data = receiver.encrypt(message, serialized_public_key)
        encrypted_session_key, nonce, ciphertext, tag = encrypted_data

        print("\nEncrypted Data: ", ciphertext.hex())  # Convert to hex for display
        print("\nEncrypted Session Key: ", encrypted_session_key.hex())
        print("\nNonce: ", nonce.hex())
        print("\nTag: ", tag.hex())

    elif option == 'd':
        # Receiver decrypts the message
        encrypted_session_key = bytes.fromhex(input("Enter the encrypted_session_key: "))
        nonce = bytes.fromhex(input("Enter the nonce: "))
        ciphertext = bytes.fromhex(input("Enter the ciphertext: "))
        tag = bytes.fromhex(input("Enter the tag: "))

        decrypted_message = receiver.decrypt((encrypted_session_key, nonce, ciphertext, tag)).decode('utf-8')
        print("\nDecrypted Message: ", decrypted_message)
    else:
        print("Invalid choice!")

if __name__ == "__main__":
    main()
