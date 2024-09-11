from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization


def generate_ssh_keypair(key_type, key_size):
    if key_type == 'rsa':
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
    elif key_type == 'ecdsa':
        private_key = ec.generate_private_key(
            ec.SECP256R1()
        )
    else:
        raise ValueError("Unsupported key type")

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )

    return private_key_pem.decode(), public_key_pem.decode()