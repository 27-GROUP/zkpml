# SecureEncryption

SecureEncryption is a Python script that provides a straightforward interface for RSA-AES hybrid encryption. It allows users to encrypt a message using a combination of RSA and AES-GCM encryption and subsequently decrypt it.

## Features

- **Persistent RSA Key Pair**: Generates and saves an RSA key pair (public and private keys) to disk (`private_key.pem` and `public_key.pem`). The keys are used across sessions, ensuring that data encrypted in one session can be decrypted in another using the saved RSA key pair.
- **RSA-AES Hybrid Encryption**: Utilizes RSA for encrypting a random AES session key and AES-GCM for encrypting the actual data.
- **User-Friendly Interface**: Allows users to choose between encrypting and decrypting messages via a simple command-line interface.

## Requirements

- Python 3
- `cryptography` library. Install using pip:
  ```bash
  pip install cryptography
  ```

## Usage

1. Clone the repository or download the `encrypt.py` script.
2. Run the script:
   ```bash
   python encrypt.py
   ```
3. Follow the on-screen prompts to either encrypt or decrypt a message.

## Encrypting a Message

1. Choose the "Encrypt" option.
2. Input the plaintext message.
3. The program will display the encrypted data, encrypted session key, nonce, and tag.

## Decrypting a Message

1. Choose the "Decrypt" option.
2. Input the required encrypted session key, nonce, ciphertext, and tag.
3. The program will display the decrypted message.

## Note

Keep the `private_key.pem` and `public_key.pem` files secure. Anyone with access to the private key will be able to decrypt messages encrypted with the associated public key.

