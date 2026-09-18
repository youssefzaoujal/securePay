"""Génère une mini PKI lab (CA + serveur + client payment). Jamais en prod telle quelle."""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _certs_dir() -> Path:
    return Path(os.getenv("LEGACY_CERTS_DIR", "/certs"))


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _dump_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def _dump_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _name(common: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])


def generate(directory: Path | None = None) -> Path:
    dest = directory or _certs_dir()
    dest.mkdir(parents=True, exist_ok=True)
    marker = dest / "ca.crt"
    if marker.exists() and (dest / "server.crt").exists() and (dest / "payment-client.crt").exists():
        return dest

    now = dt.datetime.now(dt.timezone.utc)
    until = now + dt.timedelta(days=365)

    ca_key = _key()
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("SecurePay Lab CA"))
        .issuer_name(_name("SecurePay Lab CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(until)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    server_key = _key()
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("legacy-core"))
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(until)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("legacy-core"),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    client_key = _key()
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("payment-client"))
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(until)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    (dest / "ca.crt").write_bytes(_dump_cert(ca_cert))
    (dest / "ca.key").write_bytes(_dump_key(ca_key))
    (dest / "server.crt").write_bytes(_dump_cert(server_cert))
    (dest / "server.key").write_bytes(_dump_key(server_key))
    (dest / "payment-client.crt").write_bytes(_dump_cert(client_cert))
    (dest / "payment-client.key").write_bytes(_dump_key(client_key))
    return dest


if __name__ == "__main__":
    generate()
