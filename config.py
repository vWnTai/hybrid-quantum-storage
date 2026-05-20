import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent
KEYS_DIR = BASE_DIR / "keys"
ENCRYPTED_DIR = BASE_DIR / "encrypted"
DECRYPTED_DIR = BASE_DIR / "decrypted"
LOGS_DIR = BASE_DIR / "logs"
METADATA_DIR = BASE_DIR / "metadata"

# Crypto Constants
AES_KEY_SIZE = 32      # 256 bits
AES_NONCE_SIZE = 12    # 96 bits (GCM Standard)
