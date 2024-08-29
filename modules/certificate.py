import string
import secrets
import ipaddress
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import pytz

vietnam_tz = pytz.timezone('Asia/Ho_Chi_Minh')


class CertCSR(object):
    # Define CSR attributes
    def __init__(
            self,
            common_name,
            alternative_names,
            key_size,
            key_type,
            passphrase,
            auth_type="server",
            contry_name="VN",
            state="Ha Noi",
            locality="Ha Noi",
            organization="Example Co LTD",
            email="test@example.com",
    ):
        self.common_name = common_name
        self.alternative_names = alternative_names
        self.country_name = contry_name
        self.state = state
        self.locality = locality
        self.organization = organization
        self.email = email
        self.key_type = key_type
        self.key_size = key_size
        self.passphrase = passphrase
        self.auth_type = auth_type

    @staticmethod
    def is_valid_ip(ip_str):
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    @staticmethod
    def generate_passphrase(length):
        exclude_char = r"\'\`\"\|\;\\\{\}\[\]\(\)\/"
        characters = "".join(set(string.ascii_letters + string.digits + string.punctuation) - set(exclude_char))
        pass_phrase = ''.join(secrets.choice(characters) for _ in range(length))
        return pass_phrase

    def generate_csr(self):
        if self.is_valid_ip(self.common_name):
            san = x509.IPAddress(ipaddress.ip_address(self.common_name))
        else:
            san = x509.DNSName(self.common_name)
        sans = [san]

        # Split san alter name by commas
        for s in self.alternative_names.split(','):
            s = s.strip()
            if self.is_valid_ip(s):
                sans.append(x509.IPAddress(ipaddress.ip_address(s)))
            else:
                sans.append(x509.DNSName(s))

        # Generate key pair
        if self.key_type == 'rsa':
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=int(self.key_size),
                backend=default_backend()
            )
        else:
            private_key = ec.generate_private_key(
                ec.SECP256R1(),
                default_backend()
            )

        # Serialize private key to PEM format
        pem_private_key_encrypted = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(self.passphrase.encode())
        )

        # Check auth type
        if self.auth_type == 'client':
            extended_key_usage = [ExtendedKeyUsageOID.CLIENT_AUTH]
        else:
            extended_key_usage = [
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]

        # Generate Attributes
        subject_name = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.country_name),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, self.locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization),
            x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, self.email),
        ]
        csr_builder = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(subject_name)
            )
            .add_extension(
                x509.SubjectAlternativeName(sans),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage(extended_key_usage),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
                ),
                critical=False,
            )
        )

        csr_builder = csr_builder.sign(private_key, hashes.SHA256(), default_backend())
        # Serialize CSR to PEM format
        csr = csr_builder.public_bytes(serialization.Encoding.PEM)
        output = {
            'csr': csr.decode(),
            'private_key_encrypted': pem_private_key_encrypted.decode()
        }
        return output
