import socket
import ssl
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from CA import CertificateAuthority, RegistrationAuthority


class Server:
    def __init__(self, host='localhost', port=10443):
        self.host = host
        self.port = port
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.conn = None

    def send_msg(self, msg):
        if self.conn:
            self.conn.send(msg)

    def rcv_msg(self):
        if self.conn:
            return self.conn.recv(1024)

    def start_tls(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile='server-cert.pem', keyfile='server-private-key.pem')

        context.load_verify_locations(cafile='ca-cert.pem')
        context.verify_mode = ssl.CERT_OPTIONAL#REQUIRED
        self.sock.listen(1)
        self.conn, self.addr = self.sock.accept()
        try:
            self.conn = context.wrap_socket(self.conn, server_side=True)
            print('TLS handshake completed.')
            return True
        except ssl.SSLError as e:
            print(f'TLS handshake failed: {e}')
            return False

    def generate_key_pair(self):
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    def generate_certificate(self):
        csr_key_pair = self.generate_key_pair()
        # print("A",csr_key_pair.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))

        ra = RegistrationAuthority()
        # csr = ra.generate_certificate_signing_request(csr_key_pair)
        csr = ra.generate_certificate_signing_request(csr_key_pair, 'localhost')
        ca = CertificateAuthority()
        ca_key = ca.generate_key_pair()
        certificate = ra.send_csr_to_ca_and_get_certificate(csr, ca.ca_crt)
        if certificate:
            with open('server-cert.pem', 'wb') as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))
            with open('server-private-key.pem', 'wb') as f:
                f.write(csr_key_pair.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
            return True
        else:
            return False

    def send_ca_and_server_certificates_to_client(self):
        with open('server-cert.pem', 'rb') as f:
            server_cert_data = f.read()
        with open('ca-cert.pem', 'rb') as f:
            ca_cert_data = f.read()

        self.send_msg(server_cert_data +b"~~~"+ ca_cert_data)

    # def send_certificate_to_client(self):
    #     with open('server-cert.pem', 'rb') as f:
    #         certificate_data = f.read()
    #     self.send_msg(certificate_data)


if __name__ == "__main__":
    server = Server()

    if server.generate_certificate():
        print('Certificate obtained and created successfully.')
        if server.start_tls():
            server.send_ca_and_server_certificates_to_client()
    else:
        print('Failed to obtain or create certificate.')

    if server.conn:
        server.conn.close()
