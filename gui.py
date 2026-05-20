import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import threading
import time
from pathlib import Path
import os

import config
from utils import logger, ensure_directories
import kyber_utils
from encrypt import encrypt_file
from decrypt import decrypt_file

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except ImportError:
    HAS_DND = False
    logger.info("tkinterdnd2 not installed. Drag and drop disabled.")

class PQCApp(TkinterDnD.Tk if HAS_DND else tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PQC File Encryptor (ML-KEM-512 & AES-256-GCM)")
        self.geometry("850x650")
        self.configure(bg="#1E1E1E")
        self.selected_file = None
        
        self.setup_styles()
        self.create_ui()
        
        if HAS_DND:
            self.drop_target_register(DND_FILES)
            self.dnd_bind('<<Drop>>', self.on_drop)
            
        threading.Thread(target=self.init_system, daemon=True).start()

    def setup_styles(self):
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.style.configure("TFrame", background="#1E1E1E")
        self.style.configure("TLabel", background="#1E1E1E", foreground="#CCCCCC", font=("Consolas", 10))
        self.style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"), foreground="#FFFFFF")
        
        self.style.configure("Action.TButton", font=("Segoe UI", 11, "bold"), background="#007ACC", foreground="#FFFFFF", padding=5, borderwidth=0)
        self.style.map("Action.TButton", background=[('active', '#0098FF'), ('disabled', '#333333')])
        
        self.style.configure("Secondary.TButton", font=("Segoe UI", 10), background="#333333", foreground="#FFFFFF", padding=4, borderwidth=0)
        self.style.map("Secondary.TButton", background=[('active', '#555555')])

    def create_ui(self):
        # Header
        header_frame = ttk.Frame(self)
        header_frame.pack(fill="x", pady=15)
        ttk.Label(header_frame, text="Secure Post-Quantum Hybrid Encryption", style="Header.TLabel").pack()
        ttk.Label(header_frame, text="CRYSTALS-Kyber512 (ML-KEM) + AES-256-GCM Architecture").pack()
        
        # File Area
        file_frame = ttk.Frame(self)
        file_frame.pack(fill="x", padx=30, pady=10)
        self.lbl_file = ttk.Label(file_frame, text="No file selected. Drag & Drop or Browse.", foreground="#FFA500")
        self.lbl_file.pack(side="left", fill="x", expand=True)
        
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=30, pady=5)
        ttk.Button(btn_frame, text="Browse Any File", style="Secondary.TButton", command=self.browse_encrypt).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Browse Encrypted (.enc)", style="Secondary.TButton", command=self.browse_decrypt).pack(side="left", padx=5)
        
        # Actions
        action_frame = ttk.Frame(self)
        action_frame.pack(fill="x", padx=30, pady=15)
        self.btn_encrypt = ttk.Button(action_frame, text="🔒 ENCRYPT", style="Action.TButton", command=self.do_encrypt, state="disabled")
        self.btn_encrypt.pack(side="left", expand=True, fill="x", padx=5)
        self.btn_decrypt = ttk.Button(action_frame, text="🔓 DECRYPT", style="Action.TButton", command=self.do_decrypt, state="disabled")
        self.btn_decrypt.pack(side="left", expand=True, fill="x", padx=5)

        # Progress
        self.progress = ttk.Progressbar(self, mode="indeterminate")
        self.progress.pack(fill="x", padx=30, pady=5)
        
        # Stats & Logs
        log_frame = ttk.Frame(self)
        log_frame.pack(fill="both", expand=True, padx=30, pady=10)
        ttk.Label(log_frame, text="System Console:").pack(anchor="w")
        self.txt_log = tk.Text(log_frame, height=12, bg="#121212", fg="#00FF00", font=("Consolas", 10), borderwidth=1, relief="solid")
        self.txt_log.pack(fill="both", expand=True, pady=5)
        self.txt_log.config(state="disabled")

    def log(self, msg, is_error=False):
        self.txt_log.config(state="normal")
        color = "#FF4444" if is_error else "#00FF00"
        self.txt_log.insert("end", f"> {msg}\n")
        self.txt_log.see("end")
        self.txt_log.config(state="disabled")
        if is_error: logger.error(msg)
        else: logger.info(msg)

    def init_system(self):
        self.log("Booting cryptographic systems...")
        ensure_directories()
        try:
            kyber_utils.load_keys()
            self.log("Kyber512 ML-KEM Keypair loaded successfully.")
            self.log("System Ready.")
        except Exception as e:
            self.log(f"CRITICAL INIT ERROR: {e}", True)

    def on_drop(self, event):
        path = event.data.strip('{}')
        if path.endswith('.enc'):
            self.set_file_decrypt(path)
        else:
            self.set_file_encrypt(path)

    def browse_encrypt(self):
        path = filedialog.askopenfilename(title="Select File to Encrypt")
        if path: self.set_file_encrypt(path)
            
    def browse_decrypt(self):
        path = filedialog.askopenfilename(title="Select File to Decrypt", filetypes=[("Encrypted", "*.enc")])
        if path: self.set_file_decrypt(path)

    def set_file_encrypt(self, path):
        self.selected_file = path
        self.lbl_file.config(text=f"Ready to Encrypt: {Path(path).name}", foreground="#00FF00")
        self.btn_encrypt.config(state="normal")
        self.btn_decrypt.config(state="disabled")
        
    def set_file_decrypt(self, path):
        self.selected_file = path
        self.lbl_file.config(text=f"Ready to Decrypt: {Path(path).name}", foreground="#FF00FF")
        self.btn_encrypt.config(state="disabled")
        self.btn_decrypt.config(state="normal")

    def lock_ui(self, lock=True):
        if lock:
            self.btn_encrypt.config(state="disabled")
            self.btn_decrypt.config(state="disabled")
            self.progress.start(10)
        else:
            self.progress.stop()
            # Restore proper state based on file type
            if self.selected_file:
                if self.selected_file.endswith('.enc'):
                    self.btn_encrypt.config(state="disabled")
                    self.btn_decrypt.config(state="normal")
                else:
                    self.btn_encrypt.config(state="normal")
                    self.btn_decrypt.config(state="disabled")

    def do_encrypt(self):
        if not self.selected_file: return
        self.lock_ui(True)
        threading.Thread(target=self._task_encrypt, args=(self.selected_file,), daemon=True).start()

    def _task_encrypt(self, path):
        self.log(f"Encrypting {Path(path).name}...")
        start = time.time()
        try:
            size = os.path.getsize(path)
            enc_path, meta_path = encrypt_file(path)
            elapsed = time.time() - start
            mb_ps = (size / 1048576) / elapsed if elapsed > 0 else 0
            
            self.log(f"SUCCESS! Encrypted in {elapsed:.3f}s. Throughput: {mb_ps:.2f} MB/s")
            self.log(f"Encrypted File: {enc_path.name} | Metadata: {meta_path.name}")
            self.after(0, lambda: messagebox.showinfo("Success", f"File safely encrypted.\nSaved to /encrypted"))
        except Exception as e:
            err_msg = str(e)
            self.log(f"Encryption Failed: {err_msg}", True)
            self.after(0, lambda msg=err_msg: messagebox.showerror("Security Alert", msg))
        finally:
            self.after(0, lambda: self.lock_ui(False))

    def do_decrypt(self):
        if not self.selected_file: return
        
        # Auto-locate metadata in /metadata folder
        enc_path = Path(self.selected_file)
        # Original file name from .enc is enc_path.stem
        # Actually in our logic enc_path is "filename.ext.enc". Stem is "filename.ext".
        original_name = enc_path.name[:-4] if enc_path.name.endswith(".enc") else enc_path.name
        meta_path = config.METADATA_DIR / f"{original_name}.json"
        
        if not meta_path.exists():
            messagebox.showerror("Error", f"Metadata missing at {meta_path}!")
            return

        self.lock_ui(True)
        threading.Thread(target=self._task_decrypt, args=(enc_path, meta_path), daemon=True).start()

    def _task_decrypt(self, enc_path, meta_path):
        self.log(f"Decrypting {enc_path.name}...")
        self.log("Validating AES-GCM Auth Tags & SHA-256 Hashes...")
        start = time.time()
        try:
            dec_path = decrypt_file(enc_path, meta_path)
            elapsed = time.time() - start
            
            self.log(f"SUCCESS! File decrypted and integrity strictly verified in {elapsed:.3f}s.")
            self.log(f"Restored to: {dec_path}")
            self.after(0, lambda: messagebox.showinfo("Integrity Verified", "File decrypted successfully.\nCryptographic validation passed."))
        except Exception as e:
            err_msg = str(e)
            self.log(f"Decryption/Validation Failed: {err_msg}", True)
            self.after(0, lambda msg=err_msg: messagebox.showerror("Security Violation", msg))
        finally:
            self.after(0, lambda: self.lock_ui(False))
