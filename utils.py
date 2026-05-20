import logging
import hashlib
from pathlib import Path
import config

def setup_logger():
    logger = logging.getLogger("SecureApp")
    logger.setLevel(logging.INFO)
    
    config.LOGS_DIR.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(config.LOGS_DIR / "security.log")
    ch = logging.StreamHandler()
    
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    
    if not logger.handlers:
        logger.addHandler(fh)
        logger.addHandler(ch)
        
    return logger

logger = setup_logger()

def ensure_directories():
    for d in [config.KEYS_DIR, config.ENCRYPTED_DIR, config.DECRYPTED_DIR, config.LOGS_DIR, config.METADATA_DIR]:
        d.mkdir(parents=True, exist_ok=True)

def compute_sha256(filepath: Path) -> str:
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()
