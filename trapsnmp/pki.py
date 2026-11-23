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

from trapsnmp.settings import data_dir

log = logging.getLogger("trapsnmp.pki")

APP_URI = "urn:trapsnmp:gateway"
# A one-year certificate expired while the gateway kept running, and clients
# then refused secure connections until the next restart.
CERT_DAYS = 15 * 365
RENEW_DAYS = 30
_NAME = re.compile(r"^[0-9A-Fa-f]{40}\.der$")
# Every untrusted client certificate is saved for the Publish page; keep only
# the newest ones so the folder (re-read on each console refresh) stays small.
MAX_REJECTED = 100

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
    async def ensure(cls, root: Path | None = None) -> "Pki":
        store = cls(root or (data_dir() / "pki"))
        for path in (store.cert_file.parent, store.trusted, store.crl, store.rejected):
            path.mkdir(parents=True, exist_ok=True)
        if store.key_file.is_file():
            os.chmod(store.key_file, 0o600)
        if not store.key_file.is_file() or not store.cert_file.is_file() or store._renewal_due():
            if store.cert_file.is_file():
                log.info("Replacing the OPC UA certificate at %s", store.cert_file)
            store._create()
            log.info("OPC UA certificate is %s", store.cert_file)
        return store

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
            days=CERT_DAYS,
        )
        descriptor = os.open(self.key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(dump_private_key_as_pem(key))
        try:
            os.chmod(self.key_file, 0o600)
        except OSError:
            pass
        self.cert_file.write_bytes(certificate.public_bytes(Encoding.DER))

    def days_left(self) -> int | None:
        """Whole days until the application certificate expires, or None if unreadable."""
        try:
            expires = self.certificate().not_valid_after_utc
        except Exception:
            return None
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return (expires - datetime.now(timezone.utc)).days

    def _renewal_due(self) -> bool:
        if not self.cert_file.is_file():
            return False
        left = self.days_left()
        return left is None or left <= RENEW_DAYS

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
        return self._move(name, self.rejected, self.trusted, "That certificate is not in the rejected list.")

    def reject(self, name: str) -> dict:
        return self._move(name, self.trusted, self.rejected, "That certificate is not in the trusted list.")

    def delete(self, name: str, where: str) -> dict:
        folder = {"trusted": self.trusted, "rejected": self.rejected}.get(where)
        if folder is None:
            raise ValueError("Unknown certificate list.")
        path = folder / self._named(name)
        if not path.is_file():
            raise ValueError("That certificate is not in the list.")
        path.unlink()
        return self.summary()

    def _named(self, name: str) -> str:
        if not _NAME.fullmatch(name or ""):
            raise ValueError("Unknown certificate.")
        return name

    def _move(self, name: str, source: Path, dest: Path, missing: str) -> dict:
        src = source / self._named(name)
        if not src.is_file():
            raise ValueError(missing)
        dest.mkdir(parents=True, exist_ok=True)
        _write_file(dest / src.name, src.read_bytes())
        src.unlink()
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
        _write_file(
            self.rejected / f"{_thumb(certificate).replace(':', '')}.der",
            certificate.public_bytes(Encoding.DER),
        )
        _keep_newest(self.rejected, MAX_REJECTED)
        raise ServiceError(ua.StatusCodes.BadCertificateUntrusted)


def _write_file(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _keep_newest(folder: Path, keep: int) -> None:
    files = _certs(folder)
    if len(files) <= keep:
        return
    files.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    for path in files[keep:]:
        try:
            path.unlink()
        except OSError:
            log.warning("could not remove old rejected certificate %s", path)


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
