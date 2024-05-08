# Implement-pki-from-scratch
I created a PKI environment consisting of a Certificate Authority (CA), Registration Authority (RA) and Certificate Revocation Lists (CRL). Issued 509.x certificates to users, approved certificate requests and revoked certificates. I use secure communication channels using TLS/SSL for certificate issuance and validation.

The general scenario is that, at first, the server sends a request to the RA to receive the certificate, and the RA requests the CA to receive the certificate, and when it is received (the certificate signed by the private key of the CA), the CA sends it to the server. sends
Now the server sends its certificate to its client.
The client sends the obtained certificate to the VA to find out about its authenticity, and the VA does this by communicating with the CA (using crl).
