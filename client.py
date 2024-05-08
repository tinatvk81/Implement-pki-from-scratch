import socket
import ssl
from va import CertificateValidator

class Client:
    def __init__(self, host='localhost', port=10443):
        self.host = host
        self.port = port
        self.sock = socket.socket()
        print('Connecting to', self.host, 'on port', self.port)
        self.sock.connect((host, port))
        print('Connected to server')

    def send_msg(self, msg):
        print('<--- sending message to server')
        self.sock.send(msg)

    def rcv_msg(self):
        print('---> message received from server')
        return self.sock.recv(4096)

    def start_tls(self):
        print('Initiating TLS handshake...')
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_verify_locations(cafile='ca-cert.pem')
        context.check_hostname = True  # Enable hostname verification
        context.verify_mode = ssl.CERT_OPTIONAL#_REQUIRED

        try:
            self.sock = context.wrap_socket(self.sock, server_hostname=self.host)
            print('TLS handshake completed.')
            return True
        except ssl.SSLError as e:
            print(f'TLS handshake failed: {e}')
            return False
        # context.verify_mode = ssl.CERT_REQUIRED
        # try:
        #     self.sock = context.wrap_socket(self.sock, server_hostname=self.host)
        #     print('TLS handshake completed.')
        #     return True
        # except ssl.SSLError as e:
        #     print(f'TLS handshake failed: {e}')
        #     return False

    def receive_ca_and_server_certificates(self):
        print('Receiving CA and server certificates from server')
        server_response = self.rcv_msg()
        if server_response:
            # print(server_response)
            server_cert_data, ca_cert_data = server_response.split(b'~~~')
            with open("server-cert.pem", "wb") as f:
                f.write(server_cert_data)
            with open("ca-cert.pem", "wb") as f:
                f.write(ca_cert_data)
            print("Certificates received and saved.")
    # def receive_certificate(self):
    #     print('Waiting for server to send certificate')
    #     server_response = self.rcv_msg()
    #     if server_response:
    #         with open("server-cert.pem", "wb") as f:
    #             f.write(server_response)
    #         print("Certificate received and saved as 'server-cert.pem'.")

            validator = CertificateValidator(server_response)
            if validator.validate_certificate():
                print("Certificate is valid.")
            else:

                print("Certificate validation failed.")

if __name__ == "__main__":
    print('Init client')
    client = Client()
    if client.start_tls():
        print('TLS handshake successful.')
        print('Receiving certificate from server')
        client.receive_ca_and_server_certificates()
    else:
        print('TLS handshake failed.')


# class Client:
#     def __init__(self, host='localhost', port=10443):
#         # getpeercert()
#         self.host = host
#         self.port = port
#         self.sock = socket.socket()
#         print('Connecting to', self.host, 'on port', self.port)
#         self.sock.connect((host, port))
#         print('Connected to server')
#
#     def send_msg(self, msg):
#         print('<--- sending message to server')
#         self.sock.send(msg)
#
#     def rcv_msg(self):
#         print('---> message received from server')
#         return self.sock.recv(4096)
#
#     def start_tls(self):
#         print('Initiating TLS handshake...')
#         context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
#         context.load_verify_locations(cafile='ca-cert.pem')
#         context.verify_mode = ssl.CERT_REQUIRED
#         # try:
#         #     self.sock = context.wrap_socket(self.sock, server_hostname=self.host)
#         #     # Verify server certificate
#         #     cert = self.sock.getpeercert()
#         #     common_name = 'localhost'  # Adjust this to your hostname
#         #     if common_name == cert['subject'][0][0][1]:
#         #         print('TLS handshake completed.')
#         #         return True
#         #     else:
#         #         print("Certificate common name does not match the host.")
#         #         return False
#         # except ssl.SSLError as e:
#         #     print(f'TLS handshake failed: {e}')
#         #     return False
#         try:
#             self.sock = context.wrap_socket(self.sock, server_hostname=self.host)
#             print('TLS handshake completed.')
#             return True
#         except ssl.SSLError as e:
#             print(f'TLS handshake failed: {e}')
#             return False
#
#     def receive_certificate(self):
#         print('Waiting for server to send certificate')
#         server_response = self.rcv_msg()
#         if server_response:
#             with open("server-cert.pem", "wb") as f:
#                 f.write(server_response)
#             print("Certificate received and saved as 'server-cert.pem'.")
#
#             # Validate the received certificate
#             validator = CertificateValidator(server_response)
#             if validator.validate_certificate():
#                 print("Certificate is valid.")
#             else:
#                 print("Certificate validation failed.")
#
# if __name__ == "__main__":
#     print('Init client')
#     client = Client()
#     if client.start_tls():
#         print('TLS handshake successful.')
#         print('Receiving certificate from server')
#         client.receive_certificate()
#     else:
#         print('TLS handshake failed.')
