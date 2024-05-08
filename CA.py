import os.path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta


class CertificateAuthority:
    def __init__(self, name="My CA"):
        self.ca_crt = None
        self.private_key = None
        self.name = name
        if os.path.exists("ca-cert.pem"):
            # Load existing CA certificate and private key
            with open("ca-cert.pem", "rb") as f:
                self.ca_crt = x509.load_pem_x509_certificate(f.read(), default_backend())
            with open("ca-private-key.pem", "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
        else:
            key = self.generate_key_pair()
            self.generate_self_certificate(key)

    def generate_key_pair(self):
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    def generate_self_certificate(self, private_key):
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, self.name)
        ])

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(subject)
        builder = builder.public_key(private_key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=3650))

        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        self.ca_crt = builder.sign(private_key, hashes.SHA256(), default_backend())

        # Save CA certificate and private key to files
        with open("ca-cert.pem", "wb") as f:
            f.write(self.ca_crt.public_bytes(encoding=serialization.Encoding.PEM))
        with open("ca-private-key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

    def generate_certificate(self, csr):
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(self.ca_crt.subject)
        builder = builder.public_key(csr.public_key())
        # print('B',csr.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=365))

        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        return builder.sign(self.private_key, hashes.SHA256(), default_backend())


class RegistrationAuthority:
    def __init__(self, name="My RA"):
        self.private_key = None
        self.name = name

    def generate_key_pair(self):
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    def generate_certificate_signing_request(self, private_key, name):
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, name)
        ])
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(subject)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        # Sign CSR with RA's private key
        csr = builder.sign(private_key, hashes.SHA256(), default_backend())
        return csr

    def send_csr_to_ca_and_get_certificate(self, csr, ca_cert):
        # Here, we don't need to generate a new CA key pair, we'll use the existing CA key
        ca = CertificateAuthority()
        certificate = ca.generate_certificate(csr)
        return certificate


# Example Usage
if __name__ == "__main__":
    # Initialize Certificate Authority (CA)
    ca = CertificateAuthority()
    ca_cert = ca.ca_crt
    ca_key = ca.private_key

    # Initialize Registration Authority (RA)
    ra = RegistrationAuthority()
    ra_key = ra.generate_key_pair()

    # Generate CSR (Certificate Signing Request) by RA
    csr = ra.generate_certificate_signing_request(ra_key, 'My RA')

    # Send CSR to CA and get the signed certificate
    signed_cert = ra.send_csr_to_ca_and_get_certificate(csr, ca_cert)

    # Save RA certificate and private key to files
    with open(f"ra-cert.pem", "wb") as f:
        f.write(signed_cert.public_bytes(encoding=serialization.Encoding.PEM))
    with open('ra-private-key.pem', 'wb') as f:
        f.write(ra_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    print('CA and RA done successfully ')
