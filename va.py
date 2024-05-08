# from cryptography import x509
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.x509 import load_pem_x509_certificate, load_pem_x509_crl
# from cryptography.hazmat.backends import default_backend
#
#
# def validate_certificate(cert_pem, issuer_cert_pem, crl_pem=None):
#     """Validates a certificate against its issuer's public key and optionally against a Certificate Revocation List (CRL)"""
#     # print(issuer_cert_pem)
#     # Load certificate and issuer certificate
#
#     cert = load_pem_x509_certificate(cert_pem, default_backend())
#     # print(cert)
#     # if
#     if issuer_cert_pem:
#         try:
#             issuer_cert = load_pem_x509_certificate(issuer_cert_pem, default_backend())
#         except ValueError:
#             print("Invalid issuer certificate PEM format.")
#             return False
#     # else:
#     #     print("Issuer certificate PEM is not provided.")
#     #     return False
#
#     # Verify certificate signature using issuer's public key
#     issuer_public_key = issuer_cert.public_key()
#     try:
#         issuer_public_key.verify(
#             cert.signature,
#             cert.tbs_certificate_bytes,
#             padding.PKCS1v15(),
#             cert.signature_hash_algorithm,
#         )
#     except Exception as e:
#         print("Certificate signature verification failed:", e)
#         return False
#
#     # If CRL is provided, check if the certificate is revoked
#     if crl_pem:
#         crl = load_pem_x509_crl(crl_pem, default_backend())
#         for revoked_cert in crl:
#             if cert.serial_number == revoked_cert.serial_number:
#                 print("Certificate is revoked according to CRL.")
#                 return False
#
#     return True
#
#
# if __name__ == "__main__":
#
#     # Load certificate chain and CRL from files
#     with open("_.google.crt", "rb") as f:
#         certificate_chain_pem = f.read()
#
#     with open("ca-crl.pem", "rb") as f:
#         crl_pem = f.read()
#
#     # Split certificate chain
#     certificates = certificate_chain_pem.split(b'-----END CERTIFICATE-----')
#     # print(certificates)
#     for i in range(len(certificates) - 1):
#         cert_pem = certificates[i]
#
#         if cert_pem.startswith(b'\r\n'):
#             cert_pem = cert_pem[2:]
#
#         if i < len(certificates) - 1:
#             cert_pem += b'-----END CERTIFICATE-----\n'
#
#         # Load issuer certificate
#         issuer_cert_pem = None
#         flag=False
#         if(flag==False):
#             if i < len(certificates) - 1:
#                 issuer_cert_pem = certificates[i + 1]
#                 if len(issuer_cert_pem) > 2:  # != "\r\n"
#                     issuer_cert_pem += b'-----END CERTIFICATE-----\n'
#
#                 if len(issuer_cert_pem) < 3:
#                     flag = True
#                     issuer_cert_pem = None
#
#         if (flag==True ):
#             if validate_certificate(cert_pem, cert_pem, crl_pem):
#                 print("Certificate", i + 1, "is valid.")
#             else:
#                 print("Certificate", i + 1, "is revoked or signature verification failed.")
#         else   :
#
#             # Validate certificate
#             if validate_certificate(cert_pem, issuer_cert_pem, crl_pem):
#                 print("Certificate", i + 1, "is valid.")
#             else:
#                 print("Certificate", i + 1, "is revoked or signature verification failed.")
#
#
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate, load_pem_x509_crl
from cryptography.hazmat.backends import default_backend


class CertificateValidator:
    def __init__(self, cert_pem, issuer_cert_pem=None, crl_pem=None):
        self.cert_pem = cert_pem
        self.issuer_cert_pem = issuer_cert_pem
        self.crl_pem = crl_pem

    def validate_certificate(self):
        """Validates a certificate against its issuer's public key and optionally against a Certificate Revocation List (CRL)"""
        cert = load_pem_x509_certificate(self.cert_pem, default_backend())

        if self.issuer_cert_pem:
            try:
                issuer_cert = load_pem_x509_certificate(self.issuer_cert_pem, default_backend())
            except ValueError:
                print("Invalid issuer certificate PEM format.")
                return False

            issuer_public_key = issuer_cert.public_key()
            try:
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
            except Exception as e:
                print("Certificate signature verification failed:", e)
                return False

        if self.crl_pem:
            crl = load_pem_x509_crl(self.crl_pem, default_backend())
            for revoked_cert in crl:
                if cert.serial_number == revoked_cert.serial_number:
                    print("Certificate is revoked according to CRL.")
                    return False

        return True


if __name__ == "__main__":
    with open("_.google.crt", "rb") as f:
        certificate_chain_pem = f.read()

    with open("ca-crl.pem", "rb") as f:
        crl_pem = f.read()

    certificates = certificate_chain_pem.split(b'-----END CERTIFICATE-----')
    for i in range(len(certificates) - 1):
        cert_pem = certificates[i]

        if cert_pem.startswith(b'\r\n'):
            cert_pem = cert_pem[2:]

        if i < len(certificates) - 1:
            cert_pem += b'-----END CERTIFICATE-----\n'

        issuer_cert_pem = None
        flag = False
        if flag == False:
            if i < len(certificates) - 1:
                issuer_cert_pem = certificates[i + 1]
                if len(issuer_cert_pem) > 2:
                    issuer_cert_pem += b'-----END CERTIFICATE-----\n'

                if len(issuer_cert_pem) < 3:
                    flag = True
                    issuer_cert_pem = None

        if flag == True:
            validator = CertificateValidator(cert_pem, cert_pem, crl_pem)
        else:
            validator = CertificateValidator(cert_pem, issuer_cert_pem, crl_pem)

        if validator.validate_certificate():
            print("Certificate", i + 1, "is valid.")
        else:
            print("Certificate", i + 1, "is revoked or signature verification failed.")
