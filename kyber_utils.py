import os
from pathlib import Path
from utils import logger
import config

try:
    from pqcrypto.kem.ml_kem_512 import generate_keypair, encrypt, decrypt
except ImportError:
    logger.critical("Failed to import pqcrypto ML-KEM-512. Ensure it is installed.")
    raise

def generate_and_save_keypair() -> tuple[bytes, bytes]:
    """Generates a Kyber512 (ML-KEM-512) keypair and saves it."""
    logger.info("Generating Kyber512 keypair...")
    pk, sk = generate_keypair()
    
    with open(config.KEYS_DIR / "public_key.bin", "wb") as f:
        f.write(pk)
    with open(config.KEYS_DIR / "private_key.bin", "wb") as f:
        f.write(sk)
        
    logger.info("Kyber512 keypair generated and saved.")
    return pk, sk

def load_keys() -> tuple[bytes, bytes]:
    """Loads Kyber512 keys from disk, generates if missing."""
    pk_path = config.KEYS_DIR / "public_key.bin"
    sk_path = config.KEYS_DIR / "private_key.bin"
    
    if not pk_path.exists() or not sk_path.exists():
        logger.warning("Keys not found. Generating new ones.")
        return generate_and_save_keypair()
        
    with open(pk_path, "rb") as f:
        pk = f.read()
    with open(sk_path, "rb") as f:
        sk = f.read()
    return pk, sk

def encapsulate_key(public_key: bytes) -> tuple[bytes, bytes]:
    """
    Uses ML-KEM-512 to generate a shared secret and ciphertext.
    Returns: (ciphertext, shared_secret)
    """
    return encrypt(public_key)

def decapsulate_key(ciphertext: bytes, secret_key: bytes) -> bytes:
    """
    Uses ML-KEM-512 to decapsulate the shared secret.
    Returns: shared_secret
    """
    return decrypt(secret_key, ciphertext)
