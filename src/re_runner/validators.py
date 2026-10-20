"""Only deterministic, evidence-producing validators can upgrade a finding."""
import hashlib
import re
from pathlib import Path

from .errors import InvalidInput
from .safety import Budget, read_bytes


VALIDATORS = {"private-key-possession"}


def validate_private_key(path: Path, budget: Budget) -> dict:
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, padding, rsa

    data = read_bytes(path, min(8_388_608, budget.limits["max_input_bytes"]))
    match = re.search(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", data, re.S)
    if not match:
        return {"validator": "private-key-possession", "passed": False, "reason": "No complete unencrypted supported private-key block"}
    encoded = match[0]
    try:
        loader = serialization.load_ssh_private_key if b"OPENSSH" in encoded[:80] else serialization.load_pem_private_key
        key = loader(encoded, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return {"validator": "private-key-possession", "passed": False, "reason": "Key is encrypted, malformed or unsupported"}
    public = key.public_key()
    message, control = b"re-run key possession verification v1", b"re-run negative control v1"
    if isinstance(key, rsa.RSAPrivateKey):
        algorithm = (padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        algorithm = (ec.ECDSA(hashes.SHA256()),)
    elif isinstance(key, dsa.DSAPrivateKey):
        algorithm = (hashes.SHA256(),)
    elif isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        algorithm = ()
    else:
        return {"validator": "private-key-possession", "passed": False, "reason": "Unsupported signing key type"}
    signature = key.sign(message, *algorithm)
    public.verify(signature, message, *algorithm)
    rejected = False
    try:
        public.verify(signature, control, *algorithm)
    except InvalidSignature:
        rejected = True
    fingerprint = hashlib.sha256(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    return {
        "validator": "private-key-possession", "passed": rejected,
        "assertion": "Asset contains a usable unencrypted private signing key; deployment trust and exploitability are not validated.",
        "positive_control": {"method": "sign+verify", "accepted": True},
        "negative_control": {"method": "changed-message", "accepted": not rejected},
        "public_key_sha256": fingerprint, "key_type": type(key).__name__,
    }


def run_validator(name: str, path: Path, budget: Budget) -> dict:
    if name not in VALIDATORS:
        raise InvalidInput("Unknown validator")
    budget.check()
    return validate_private_key(path, budget)


def verification_gate(validation: dict | None) -> bool:
    return bool(
        validation and validation.get("validator") in VALIDATORS
        and validation.get("passed") is True
        and validation.get("positive_control", {}).get("accepted") is True
        and validation.get("negative_control", {}).get("accepted") is False
        and validation.get("tool_run_id") and validation.get("evidence_id")
    )

