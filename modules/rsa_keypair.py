from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import getpass  # For securely obtaining the passphrase


class RSAKeyPair:
    def __init__(self, key_size=2048, passphrase=None):
        self.key_size = key_size
        self.passphrase = passphrase or getpass.getpass("Enter a passphrase to encrypt the private key: ")
        self.private_key = None
        self.public_key = None

    def generate_keypair(self):
        # Generate RSA private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def serialize_private_key(self, format='PKCS8'):
        # Determine the private key format
        if format == 'PKCS8':
            private_key_format = serialization.PrivateFormat.PKCS8
        elif format == 'TraditionalOpenSSL':
            private_key_format = serialization.PrivateFormat.TraditionalOpenSSL
        else:
            raise ValueError("Invalid private key format. Choose 'PKCS8' or 'TraditionalOpenSSL'.")

        # Serialize private key with encryption
        private_key_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=private_key_format,
            encryption_algorithm=serialization.BestAvailableEncryption(self.passphrase.encode())
        )
        return private_key_bytes

    def serialize_public_key(self, format='X509'):
        # Determine the public key format
        if format == 'X509':
            public_key_format = serialization.PublicFormat.SubjectPublicKeyInfo
        else:
            raise ValueError("Invalid public key format. Choose 'X509'.")

        # Serialize public key
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=public_key_format
        )
        return public_key_bytes


# Usage
rsa_keypair = RSAKeyPair(key_size=2048)
rsa_keypair.generate_keypair()
private_key = rsa_keypair.serialize_private_key(format='PKCS8')
public_key = rsa_keypair.serialize_public_key(format='X509')


# Print private key to screen
print(private_key.decode())

# Print public key to screen
print(public_key.decode())