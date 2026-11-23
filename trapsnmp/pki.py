"""OPC UA application certificate and client trust store."""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
from datetime import datetime, timezone
from pathlib import Path

from asyncua import ua
from asyncua.common.utils import ServiceError
from asyncua.crypto.cert_gen import (
    dump_private_key_as_pem,
    generate_private_key,
    generate_self_signed_app_certificate,
)
from asyncua.crypto.validator import CertificateValidator, CertificateValidatorOptions
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID

from trapsnmp.paths import DATA_DIR

log = logging.getLogger("trapsnmp.pki")

PKI_ROOT = DATA_DIR / "pki"
APP_URI = "urn:trapsnmp:gateway"
_NAME = re.compile(r"^[0-9A-Fa-f]{40}\.der$")

PROFILES = (
    ua.SecurityPolicyType.NoSecurity,
    ua.SecurityPolicyType.Basic256Sha256_Sign,
    ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt,
    ua.SecurityPolicyType.Aes128Sha256RsaOaep_Sign,
    ua.SecurityPolicyType.Aes128Sha256RsaOaep_SignAndEncrypt,
    ua.SecurityPolicyType.Aes256Sha256RsaPss_Sign,
    ua.SecurityPolicyType.Aes256Sha256RsaPss_SignAndEncrypt,
)


class Pki:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.cert_file = root / "own" / "cert.der"
        self.key_file = root / "own" / "private_key.pem"
        self.trusted = root / "trusted" / "certs"
        self.crl = root / "trusted" / "crl"
        self.rejected = root / "rejected"
        self.validator = ClientCertValidator(self.trusted, self.rejected)

    @classmethod
    async def ensure(cls, root: Path = PKI_ROOT) -> "Pki":
        store = cls(root)
        for path in (store.cert_file.parent, store.trusted, store.crl, store.rejected):
            path.mkdir(parents=True, exist_ok=True)
        if not store.key_file.is_file() or not store.cert_file.is_file():
            store._create()
            log.info("Created OPC UA certificate %s", store.cert_file)
        elif store._expired():
            # Clients reject an expired server certificate, so make a new one.
            # Clients that trusted the old one must trust the new thumbprint.
            store._create()
            log.warning("OPC UA certificate had expired; created a new one at %s", store.cert_file)
        return store

    def _expired(self) -> bool:
        try:
            return self.certificate().not_valid_after_utc <= datetime.now(timezone.utc)
        except Exception:
            log.warning("Could not read %s; creating a new certificate", self.cert_file, exc_info=True)
            return True

    def _create(self) -> None:
        host = socket.gethostname() or "localhost"
        names = [
            x509.UniformResourceIdentifier(APP_URI),
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]
        try:
            names.append(x509.DNSName(host))
        except ValueError:
            log.warning("Hostname %s is not a valid DNS name for the certificate", host)
        key = generate_private_key()
        certificate = generate_self_signed_app_certificate(
            key,
            "trapsnmp",
            {"organizationName": "trapsnmp"},
            names,
            [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH],
            days=365,
        )
        # Only the gateway's own account may read the private key.
        descriptor = os.open(self.key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(dump_private_key_as_pem(key))
        try:
            os.chmod(self.key_file, 0o600)
        except OSError:
            pass
        self.cert_file.write_bytes(certificate.public_bytes(Encoding.DER))

    def certificate(self) -> x509.Certificate:
        return x509.load_der_x509_certificate(self.cert_file.read_bytes())

    def summary(self) -> dict:
        cert = self.certificate()
        return {
            "subject": cert.subject.rfc4514_string(),
            "expires": _when(cert.not_valid_after_utc),
            "thumbprint": _thumb(cert),
            "uri": APP_URI,
            "path": str(self.cert_file),
            "policies": [item.name for item in PROFILES],
            "trusted": [_describe(path) for path in _certs(self.trusted)],
            "rejected": [_describe(path) for path in _certs(self.rejected)],
        }

    def trust(self, name: str) -> dict:
        if not _NAME.fullmatch(name or ""):
            raise ValueError("Unknown certificate.")
        source = self.rejected / name
        if not source.is_file():
            raise ValueError("That certificate is not in the rejected list.")
        target = self.trusted / name
        target.write_bytes(source.read_bytes())
        source.unlink()
        return self.summary()


class ClientCertValidator:
    def __init__(self, trusted: Path, rejected: Path) -> None:
        self.trusted = trusted
        self.rejected = rejected
        self._inner = CertificateValidator(
            CertificateValidatorOptions.BASIC_VALIDATION | CertificateValidatorOptions.PEER_CLIENT
        )

    async def __call__(self, certificate: x509.Certificate, application) -> None:
        await self._inner.validate(certificate, application)
        if _matches(certificate, self.trusted):
            return
        self.rejected.mkdir(parents=True, exist_ok=True)
        (self.rejected / f"{_thumb(certificate).replace(':', '')}.der").write_bytes(
            certificate.public_bytes(Encoding.DER)
        )
        raise ServiceError(ua.StatusCodes.BadCertificateUntrusted)


def _certs(folder: Path) -> list[Path]:
    if not folder.is_dir():
        return []
    return sorted(path for path in folder.iterdir() if path.suffix.lower() in (".der", ".pem") and path.is_file())


def _describe(path: Path) -> dict:
    try:
        data = path.read_bytes()
        cert = (
            x509.load_pem_x509_certificate(data)
            if path.suffix.lower() == ".pem"
            else x509.load_der_x509_certificate(data)
        )
    except Exception:
        return {"name": path.name, "subject": path.name, "thumbprint": ""}
    return {"name": path.name, "subject": cert.subject.rfc4514_string(), "thumbprint": _thumb(cert)}


def _matches(certificate: x509.Certificate, folder: Path) -> bool:
    digest = certificate.fingerprint(hashes.SHA256())
    for path in _certs(folder):
        data = path.read_bytes()
        try:
            other = (
                x509.load_pem_x509_certificate(data)
                if path.suffix.lower() == ".pem"
                else x509.load_der_x509_certificate(data)
            )
        except Exception:
            continue
        if other.fingerprint(hashes.SHA256()) == digest:
            return True
        try:
            certificate.verify_directly_issued_by(other)
        except Exception:
            continue
        else:
            return True
    return False


def _thumb(certificate: x509.Certificate) -> str:
    raw = certificate.fingerprint(hashes.SHA1()).hex().upper()
    return ":".join(raw[index : index + 2] for index in range(0, len(raw), 2))


def _when(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")
