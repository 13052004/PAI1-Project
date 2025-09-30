# gen_cert.py — genera server.key (PEM) y server.crt (PEM autofirmado)
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

# parameters
KEY_FILE = "server.key"
CERT_FILE = "server.crt"
COMMON_NAME = "localhost"

# generate RSA key pair
key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

# save private key in PEM (unencrypted — OK for testing)
with open(KEY_FILE, "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS#1
        encryption_algorithm=serialization.NoEncryption()
    ))

# construct subject/issuer
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Sevilla"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Sevilla"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"PAI1"),
    x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME),
])

# create self-signed certificate
cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow() - datetime.timedelta(minutes=1)
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=365)
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName(COMMON_NAME)]),
    critical=False
).sign(key, hashes.SHA256())

# write certificate in PEM
with open(CERT_FILE, "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print(f"Generated {KEY_FILE} and {CERT_FILE}")
