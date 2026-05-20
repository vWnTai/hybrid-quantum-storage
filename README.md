# Post-Quantum File Encryption Application using CRYSTALS-Kyber and AES-256-GCM

A professional, production-ready hybrid cryptographic desktop application that secures files against both modern computational resources and future quantum computing attacks. 

This application uses **AES-256-GCM** for high-speed symmetric data encryption and **CRYSTALS-Kyber512 (ML-KEM-512)**—the NIST standardized Key Encapsulation Mechanism—to securely encapsulate the symmetric key.

---

## 🏗️ System Architecture

The project follows a strictly modular separation of concerns:
- `config.py`: Hardcoded security constants (96-bit nonces, 256-bit AES keys) and directory structures.
- `utils.py`: Deterministic SHA-256 hashing and foundational logger setups.
- `kyber_utils.py`: Wraps the raw `pqcrypto` C-bindings for ML-KEM-512 generation, encapsulation, and decapsulation.
- `encrypt.py`: Coordinates the hybrid KEM wrap flow and metadata generation.
- `decrypt.py`: Handles integrity validations, KEM unwrapping, and strict failure scenarios.
- `gui.py`: The user interface layer, built dynamically with Tkinter using a dark-mode theme, isolating threading logic from cryptography.

### The Hybrid Encryption Workflow (KEM)

Kyber is **not** designed to encrypt arbitrary files directly. It is a Key Encapsulation Mechanism (KEM). Our software strictly obeys modern cryptographic standards:

1. **Symmetric Keygen**: A random 256-bit AES key is generated via OS entropy.
2. **Bulk Encryption**: The target file is encrypted using `AES-256-GCM` using the 256-bit key and a random 96-bit nonce.
3. **Encapsulation**: The Kyber KEM is invoked against the receiver's Kyber Public Key. It outputs a `shared_secret` and a `kyber_ciphertext`.
4. **Key Wrap (KEK)**: The `shared_secret` is utilized as a Key-Encryption-Key (KEK). The original 256-bit AES key is encrypted (wrapped) by this KEK using AES-256-GCM.
5. **Storage**: The encrypted file is saved as `.enc` in `/encrypted`. The `kyber_ciphertext` and wrapped AES key are stored in `/metadata/` as JSON.

---

## 🔒 Security Analysis & Threat Model

### Cryptographic Security
- **Authentication**: `AES-GCM` provides an implicit 16-byte authentication tag. Decryption automatically fails if a single bit of the file or wrapped key is tampered with. This eliminates padding oracle attacks (which plague AES-CBC).
- **Integrity**: We maintain double-layered integrity. GCM verifies chunk boundaries, and an overarching SHA-256 hash stored in the metadata validates the final decrypted plaintext.

### Decryption Validations Handled
The software actively detects and prevents:
- Missing or corrupted `.enc` / `.json` files.
- Invalid AES-GCM Auth Tags on both the KEK unwrap and bulk data decrypt.
- Path Traversal attempts embedded in malicious `original_filename` metadata.
- SHA-256 mismatches confirming file tampering or hardware-level corruption.

---

## 🎓 Post-Quantum Cryptography Explained

### Post-Quantum Cryptography (PQC) Overview
Quantum computers utilize qubits and superposition to process states exponentially faster than classical bits. Algorithms like Shor's Algorithm prove that a sufficiently powerful quantum computer can solve prime factorization and discrete logarithms in polynomial time. PQC refers to classical algorithms (running on normal computers) that are mathematically resilient against quantum attacks.

### CRYSTALS-Kyber Explanation
Kyber (standardized as ML-KEM) is a lattice-based cryptography mechanism. Its security relies on the hardness of the **Module Learning With Errors (MLWE)** problem. Essentially, it hides data by adding mathematical "noise" to vectors across a multi-dimensional lattice, making it impossible for classical or quantum algorithms to efficiently locate the original vector.

### RSA vs Kyber
- **RSA**: Relies on Integer Factorization. Easily broken by Shor's Algorithm on a quantum machine. Generates massive keys and is slower to compute.
- **Kyber**: Relies on Lattice Math (MLWE). Believed to be impervious to quantum attacks. Generates smaller ciphertexts compared to some classical schemes and is remarkably fast for key encapsulation.

---

## 💾 Installation

### Prerequisites
- Python 3.11+
- C Compiler (for the underlying pqcrypto CFFI bindings)

### Setup
1. Navigate to the project root.
2. Install the requirements:
   ```bash
   pip install -r requirements.txt
   ```
*(Ensure `pqcrypto` and `cryptography` are successfully installed).*

---

## 🚀 Usage Guide

1. **Start the GUI**:
   ```bash
   python main.py
   ```
2. **First Boot**: The system automatically generates your Kyber Public/Private keys in `/keys` and builds the necessary folders (`/encrypted`, `/decrypted`, `/logs`, `/metadata`).
3. **Encryption**: 
   - Click "Browse Any File" and select your target.
   - Click "ENCRYPT".
   - The file will securely land in `/encrypted/` and metadata in `/metadata/`.
4. **Decryption**:
   - Click "Browse Encrypted (.enc)".
   - Select the encrypted file. The system will automatically fetch the paired JSON from `/metadata/`.
   - Click "DECRYPT". The validated file will output to `/decrypted/`.

---

## 📸 Screenshots

*(Placeholder for GUI Visuals)*

> **Figure 1**: PQC App Dark Mode Interface  
> `[ Add UI Screenshot ]`

> **Figure 2**: Successful Integrity Validation Console Log  
> `[ Add Console Screenshot ]`
