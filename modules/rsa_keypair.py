from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import getpass  # For securely obtaining the passphrase


def generate_rsa_keypair():
    # Prompt the user for a passphrase
    passphrase = getpass.getpass("Enter a passphrase to encrypt the private key: ")

    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # You can increase key size if needed
        backend=default_backend()
    )

    # Serialize private key to PKCS#8 format with encryption
    private_key_pkcs8 = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
    )

    # Get the public key
    public_key = private_key.public_key()

    # Serialize public key to X.509 format (PEM encoded)
    public_key_x509 = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pkcs8, public_key_x509


# Usage
private_key, public_key = generate_rsa_keypair()

# Save private key to a file
with open("private_key_pkcs8.pem", "wb") as priv_file:
    priv_file.write(private_key)

# Save public key to a file
with open("public_key_x509.pem", "wb") as pub_file:
    pub_file.write(public_key)