import os
import json
import base64
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

import config
from utils import logger, compute_sha256
import kyber_utils

def encrypt_file(file_path: str | Path) -> tuple[Path, Path]:
    """
    Executes hybrid KEM encryption flow.
    1. AES-256 random key generation
    2. AES-256-GCM file encryption
    3. Kyber512 KEM encapsulation
    4. KEK derivation and AES key wrapping
    """
    file_path = Path(file_path).resolve()
    if not file_path.exists():
        raise FileNotFoundError(f"File {file_path} not found.")
        
    logger.info(f"Starting encryption process for {file_path.name}")
    
    # 1. Calculate original file hash
    original_sha256 = compute_sha256(file_path)
    
    # 2. Generate random AES-256 key and Nonce
    aes_key = AESGCM.generate_key(bit_length=config.AES_KEY_SIZE * 8)
    file_nonce = os.urandom(config.AES_NONCE_SIZE)
    
    # 3. Encrypt file using AES-256-GCM
    with open(file_path, "rb") as f:
        plaintext = f.read()
        
    aesgcm = AESGCM(aes_key)
    # Ciphertext includes the 16-byte authentication tag at the end
    encrypted_file_data = aesgcm.encrypt(file_nonce, plaintext, None)
    
    # Generate unique suffix based on timestamp
    timestamp_suffix = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    unique_filename = f"{file_path.name}_{timestamp_suffix}"
    
    enc_file_path = config.ENCRYPTED_DIR / f"{unique_filename}.enc"
    with open(enc_file_path, "wb") as f:
        f.write(encrypted_file_data)
        
    # 4. Use Kyber KEM to encapsulate a shared secret
    public_key, _ = kyber_utils.load_keys()
    kyber_ct, shared_secret = kyber_utils.encapsulate_key(public_key)
    
    # 5. Wrap the AES key using KEK (shared_secret)
    kek = shared_secret[:config.AES_KEY_SIZE].ljust(config.AES_KEY_SIZE, b'\0')
    kek_nonce = os.urandom(config.AES_NONCE_SIZE)
    kek_aesgcm = AESGCM(kek)
    wrapped_aes_key = kek_aesgcm.encrypt(kek_nonce, aes_key, None)
    
    # 6. Save Metadata
    # We combine file_nonce and kek_nonce into one field or store them separately.
    # The requirement asks for "nonce", we will store both combined or just the file nonce 
    # and the kek nonce wrapped inside "wrapped_aes_key" to be safe.
    # Actually let's explicitly store the 12-byte file nonce and the wrapped AES key.
    # We can prepend kek_nonce to wrapped_aes_key (standard practice).
    combined_wrapped_key = kek_nonce + wrapped_aes_key
    
    metadata = {
        "original_filename": file_path.name,
        "sha256": original_sha256,
        "nonce": base64.b64encode(file_nonce).decode('utf-8'),
        "kyber_ciphertext": base64.b64encode(kyber_ct).decode('utf-8'),
        "wrapped_aes_key": base64.b64encode(combined_wrapped_key).decode('utf-8'),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    meta_path = config.METADATA_DIR / f"{unique_filename}.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)
        
    logger.info(f"Encryption successful. Encrypted: {enc_file_path.name}, Meta: {meta_path.name}")
    return enc_file_path, meta_path
