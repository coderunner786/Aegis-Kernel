import os
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# Embedded Master Public Key (Hardcoded/Baked into the agent client)
# Used exclusively to VERIFY artifacts on endpoints.
PROJECT_ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
PUBLIC_KEY_FILE = PROJECT_ROOT / ".aegis_pubkey.pem"
PRIVATE_KEY_FILE = PROJECT_ROOT / ".aegis_privkey.pem"

# Fallback default embedded public key (generated once for the project release)
EMBEDDED_PUBLIC_KEY_HEX = (
    "302a300506032b6570032100"  # DER standard header prefix for Ed25519
)

class SecurityError(Exception):
    pass

def generate_keypair():
    """Generates an Ed25519 private/public keypair (for build/CI server use)."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(priv_pem)

    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(pub_pem)

    print(f"[+] Generated asymmetric Ed25519 keypair:\n    - {PRIVATE_KEY_FILE} (KEEP SECRET)\n    - {PUBLIC_KEY_FILE} (Public)")

def load_private_key() -> ed25519.Ed25519PrivateKey:
    """Loads the signing private key from disk or environment."""
    if not PRIVATE_KEY_FILE.exists():
        raise SecurityError(
            f"[FATAL] Private key {PRIVATE_KEY_FILE} not found on build machine.\n"
            "Generate one first using: python -c \"from core.security import generate_keypair; generate_keypair()\""
        )
    with open(PRIVATE_KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key() -> ed25519.Ed25519PublicKey:
    """Loads the public verification key."""
    if PUBLIC_KEY_FILE.exists():
        with open(PUBLIC_KEY_FILE, "rb") as f:
            return serialization.load_pem_public_key(f.read())
    
    raise SecurityError(f"[FATAL] Public key {PUBLIC_KEY_FILE} missing. Cannot verify artifact integrity.")

def sign_artifact(file_path: Path, sig_output_path: Path):
    """Signs a binary/model file using the Ed25519 private key (Build Pipeline)."""
    private_key = load_private_key()
    
    with open(file_path, "rb") as f:
        data = f.read()

    # Ed25519 signs raw bytes deterministically
    signature = private_key.sign(data)
    
    with open(sig_output_path, "wb") as f:
        f.write(signature)

def verify_artifact_integrity(file_path: Path, sig_path: Path) -> bool:
    """
    Verifies artifact integrity using the Ed25519 public key (Agent Runtime).
    Returns True if signature is valid, False otherwise.
    """
    if not file_path.exists() or not sig_path.exists():
        return False

    try:
        public_key = load_public_key()
        with open(file_path, "rb") as f:
            data = f.read()
        with open(sig_path, "rb") as f:
            signature = f.read()

        public_key.verify(signature, data)
        return True
    except (InvalidSignature, SecurityError, OSError, ValueError, TypeError):
        return False