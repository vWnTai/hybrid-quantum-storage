import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

import config
from utils import logger, compute_sha256
import kyber_utils

def decrypt_file(enc_file_path: str | Path, meta_file_path: str | Path) -> Path:
    """
    Executes hybrid KEM decryption flow with strict security validation.
    """
    enc_file_path = Path(enc_file_path).resolve()
    meta_file_path = Path(meta_file_path).resolve()
    
    # Validation 1: Missing files
    if not enc_file_path.exists():
        raise FileNotFoundError(f"Encrypted file missing: {enc_file_path}")
    if not meta_file_path.exists():
        raise FileNotFoundError(f"Metadata file missing: {meta_file_path}")
        
    logger.info(f"Starting decryption process for {enc_file_path.name}")
    
    # Validation 2: Metadata format and corruption
    try:
        with open(meta_file_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)
    except json.JSONDecodeError:
        raise ValueError("Metadata file is corrupted or not valid JSON.")
        
    required_keys = ["original_filename", "sha256", "nonce", "kyber_ciphertext", "wrapped_aes_key"]
    for key in required_keys:
        if key not in metadata:
            raise ValueError(f"Metadata missing critical field: {key}")
            
    # Decode metadata
    try:
        original_filename = metadata["original_filename"]
        original_sha256 = metadata["sha256"]
        file_nonce = base64.b64decode(metadata["nonce"])
        kyber_ct = base64.b64decode(metadata["kyber_ciphertext"])
        combined_wrapped_key = base64.b64decode(metadata["wrapped_aes_key"])
    except Exception as e:
        raise ValueError(f"Metadata decoding failed (base64 corruption): {str(e)}")

    # 1. Recover KEK using Kyber
    _, secret_key = kyber_utils.load_keys()
    try:
        shared_secret = kyber_utils.decapsulate_key(kyber_ct, secret_key)
    except Exception as e:
        raise ValueError("Kyber decapsulation failed. Incorrect private key or corrupted ciphertext.")
        
    # 2. Derive KEK and unwrap AES key
    kek = shared_secret[:config.AES_KEY_SIZE].ljust(config.AES_KEY_SIZE, b'\0')
    kek_nonce = combined_wrapped_key[:config.AES_NONCE_SIZE]
    wrapped_aes_key = combined_wrapped_key[config.AES_NONCE_SIZE:]
    
    kek_aesgcm = AESGCM(kek)
    try:
        aes_key = kek_aesgcm.decrypt(kek_nonce, wrapped_aes_key, None)
    except InvalidTag:
        raise ValueError("AES key unwrapping failed (Invalid Auth Tag). KEK is wrong or data corrupted.")
        
    # 3. Decrypt file contents
    with open(enc_file_path, "rb") as f:
        encrypted_file_data = f.read()
        
    aesgcm = AESGCM(aes_key)
    try:
        # Validation 3: AES-GCM Auth tag is implicitly verified here
        plaintext = aesgcm.decrypt(file_nonce, encrypted_file_data, None)
    except InvalidTag:
        raise ValueError("File decryption failed (Invalid Auth Tag). File was tampered with.")
        
    # 4. Save to decrypted directory
    dec_file_path = config.DECRYPTED_DIR / original_filename
    
    # Path traversal prevention
    if dec_file_path.resolve().parent != config.DECRYPTED_DIR.resolve():
        raise SecurityError("Path traversal attempt detected in original filename!")
        
    with open(dec_file_path, "wb") as f:
        f.write(plaintext)
        
    # Validation 4: SHA256 integrity validation
    restored_hash = compute_sha256(dec_file_path)
    if restored_hash != original_sha256:
        # Clean up corrupted file
        dec_file_path.unlink()
        raise ValueError("SHA256 Hash mismatch! The decrypted file is compromised.")
        
    logger.info(f"Decryption and integrity checks passed. Saved to: {dec_file_path}")
    return dec_file_path

class SecurityError(Exception):
    pass
