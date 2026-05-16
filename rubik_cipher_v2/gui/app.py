import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

from ..core.cipher import RubikCipher
from ..analysis.security_analysis import SecurityAnalyzer

# Catppuccin Mocha palette
C = {
    "base":    "#1e1e2e",
    "mantle":  "#181825",
    "surface0":"#313244",
    "surface1":"#45475a",
    "overlay0":"#6c7086",
    "text":    "#cdd6f4",
    "mauve":   "#cba6f7",
    "blue":    "#89b4fa",
    "green":   "#a6e3a1",
    "red":     "#f38ba8",
    "yellow":  "#f9e2af",
}


class RubikCipherApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("RUBIK Cipher v2")
        self.geometry("880x700")
        self.minsize(640, 520)
        self.configure(bg=C["base"])

        self._key_var = tk.StringVar()
        self._status_var = tk.StringVar(value="Ready")
        self._busy = False

        self._build_ui()

    # ------------------------------------------------------------------ UI build

    def _build_ui(self):
        self._build_header()
        self._build_key_row()
        self._build_notebook()
        self._build_statusbar()

    def _build_header(self):
        hdr = tk.Frame(self, bg=C["mantle"], pady=14)
        hdr.pack(fill=tk.X)
        tk.Label(
            hdr, text="RUBIK Cipher", font=("Consolas", 20, "bold"),
            bg=C["mantle"], fg=C["mauve"],
        ).pack(side=tk.LEFT, padx=20)
        tk.Label(
            hdr, text="v2  ·  Symmetric Block Cipher  ·  CBC + PKCS7",
            font=("Consolas", 10), bg=C["mantle"], fg=C["overlay0"],
        ).pack(side=tk.LEFT, pady=6)

    def _build_key_row(self):
        frame = tk.Frame(self, bg=C["base"], pady=10)
        frame.pack(fill=tk.X, padx=20)

        tk.Label(
            frame, text="Encryption Key:", font=("Consolas", 11),
            bg=C["base"], fg=C["text"],
        ).pack(side=tk.LEFT)

        self._key_entry = tk.Entry(
            frame, textvariable=self._key_var, font=("Consolas", 11),
            show="•", bg=C["surface0"], fg=C["text"],
            insertbackground=C["text"], relief=tk.FLAT, bd=0, width=38,
        )
        self._key_entry.pack(side=tk.LEFT, padx=(8, 0), ipady=5, ipadx=4)

        self._show_btn = tk.Button(
            frame, text="Show", font=("Consolas", 9),
            bg=C["surface1"], fg=C["text"], relief=tk.FLAT, bd=0,
            padx=10, cursor="hand2",
            command=self._toggle_key_visibility,
        )
        self._show_btn.pack(side=tk.LEFT, padx=6)

    def _build_notebook(self):
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("TNotebook", background=C["base"], borderwidth=0)
        style.configure(
            "TNotebook.Tab", background=C["surface0"], foreground=C["text"],
            font=("Consolas", 10), padding=[14, 6],
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", C["mauve"])],
            foreground=[("selected", C["mantle"])],
        )

        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 4))

        enc_tab = tk.Frame(nb, bg=C["base"])
        dec_tab = tk.Frame(nb, bg=C["base"])
        ana_tab = tk.Frame(nb, bg=C["base"])

        nb.add(enc_tab, text="   Encrypt   ")
        nb.add(dec_tab, text="   Decrypt   ")
        nb.add(ana_tab, text="   Analysis   ")

        self._build_encrypt_tab(enc_tab)
        self._build_decrypt_tab(dec_tab)
        self._build_analysis_tab(ana_tab)

    def _build_encrypt_tab(self, parent):
        self._lbl(parent, "Plaintext:").pack(anchor=tk.W, padx=14, pady=(14, 2))
        self._plain_in = self._textarea(parent)
        self._plain_in.pack(fill=tk.BOTH, expand=True, padx=14)

        row = tk.Frame(parent, bg=C["base"], pady=8)
        row.pack(fill=tk.X, padx=14)
        self._btn(row, "Encrypt  ▶", C["mauve"], C["mantle"], self._do_encrypt).pack(side=tk.LEFT)
        self._btn(row, "Clear", C["surface1"], C["text"], self._clear_encrypt).pack(side=tk.LEFT, padx=8)

        self._lbl(parent, "Ciphertext (Base64):").pack(anchor=tk.W, padx=14, pady=(4, 2))
        self._cipher_out = self._textarea(parent, readonly=True, fg=C["green"])
        self._cipher_out.pack(fill=tk.BOTH, expand=True, padx=14)

        row2 = tk.Frame(parent, bg=C["base"], pady=6)
        row2.pack(fill=tk.X, padx=14)
        self._btn(row2, "Copy Ciphertext", C["surface1"], C["text"], self._copy_ciphertext).pack(side=tk.LEFT)

    def _build_decrypt_tab(self, parent):
        self._lbl(parent, "Ciphertext (Base64):").pack(anchor=tk.W, padx=14, pady=(14, 2))
        self._cipher_in = self._textarea(parent)
        self._cipher_in.pack(fill=tk.BOTH, expand=True, padx=14)

        row = tk.Frame(parent, bg=C["base"], pady=8)
        row.pack(fill=tk.X, padx=14)
        self._btn(row, "Decrypt  ▶", C["blue"], C["mantle"], self._do_decrypt).pack(side=tk.LEFT)
        self._btn(row, "Paste from Encrypt", C["surface1"], C["text"], self._paste_from_encrypt).pack(side=tk.LEFT, padx=8)
        self._btn(row, "Clear", C["surface1"], C["text"], self._clear_decrypt).pack(side=tk.LEFT, padx=4)

        self._lbl(parent, "Decrypted Plaintext:").pack(anchor=tk.W, padx=14, pady=(4, 2))
        self._plain_out = self._textarea(parent, readonly=True, fg=C["green"])
        self._plain_out.pack(fill=tk.BOTH, expand=True, padx=14, pady=(0, 10))

    def _build_analysis_tab(self, parent):
        info = tk.Frame(parent, bg=C["base"], pady=10)
        info.pack(fill=tk.X, padx=14)
        tk.Label(
            info, text="Cryptographic analysis using the current key.",
            font=("Consolas", 9), bg=C["base"], fg=C["overlay0"],
        ).pack(side=tk.LEFT)

        row = tk.Frame(parent, bg=C["base"], pady=4)
        row.pack(fill=tk.X, padx=14)
        self._btn(row, "Run Analysis", C["red"], C["mantle"], self._do_analysis).pack(side=tk.LEFT)
        tk.Label(
            row, text="  (avalanche, key sensitivity, speed)",
            font=("Consolas", 9), bg=C["base"], fg=C["overlay0"],
        ).pack(side=tk.LEFT)

        self._analysis_out = self._textarea(parent, readonly=True, fg=C["text"])
        self._analysis_out.pack(fill=tk.BOTH, expand=True, padx=14, pady=(8, 10))

    def _build_statusbar(self):
        bar = tk.Frame(self, bg=C["mantle"], pady=5)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Label(
            bar, textvariable=self._status_var,
            font=("Consolas", 9), bg=C["mantle"], fg=C["green"],
        ).pack(side=tk.LEFT, padx=14)

    # ------------------------------------------------------------------ helpers

    def _lbl(self, parent, text):
        return tk.Label(parent, text=text, font=("Consolas", 10),
                        bg=C["base"], fg=C["text"])

    def _btn(self, parent, text, bg, fg, cmd):
        return tk.Button(
            parent, text=text, font=("Consolas", 10, "bold"),
            bg=bg, fg=fg, relief=tk.FLAT, bd=0,
            padx=14, pady=6, cursor="hand2", command=cmd,
        )

    def _textarea(self, parent, readonly=False, fg=None):
        bg = C["mantle"] if readonly else C["surface0"]
        t = scrolledtext.ScrolledText(
            parent, font=("Consolas", 10),
            bg=bg, fg=fg or C["text"],
            insertbackground=C["text"],
            relief=tk.FLAT, bd=0, height=7, wrap=tk.WORD,
            state=tk.DISABLED if readonly else tk.NORMAL,
        )
        return t

    def _set_text(self, widget, text):
        widget.config(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert("1.0", text)
        widget.config(state=tk.DISABLED)

    def _get_text(self, widget):
        return widget.get("1.0", tk.END).rstrip("\n")

    def _get_key(self):
        key = self._key_var.get().strip()
        if not key:
            messagebox.showwarning("No Key", "Please enter an encryption key.")
            return None
        return key

    def _set_status(self, msg):
        self._status_var.set(msg)

    # ------------------------------------------------------------------ toggle key visibility

    def _toggle_key_visibility(self):
        if self._key_entry.cget("show") == "•":
            self._key_entry.config(show="")
            self._show_btn.config(text="Hide")
        else:
            self._key_entry.config(show="•")
            self._show_btn.config(text="Show")

    # ------------------------------------------------------------------ encrypt / decrypt

    def _do_encrypt(self):
        key = self._get_key()
        if key is None:
            return
        plaintext = self._get_text(self._plain_in)
        if not plaintext:
            messagebox.showwarning("Empty Input", "Please enter plaintext to encrypt.")
            return
        self._set_status("Deriving key and encrypting...")
        self.update_idletasks()

        def run():
            try:
                ct = RubikCipher(key).encrypt(plaintext)
                self.after(0, self._set_text, self._cipher_out, ct)
                self.after(0, self._set_status, "Encryption complete.")
            except Exception as exc:
                self.after(0, messagebox.showerror, "Encryption Error", str(exc))
                self.after(0, self._set_status, "Encryption failed.")

        threading.Thread(target=run, daemon=True).start()

    def _do_decrypt(self):
        key = self._get_key()
        if key is None:
            return
        ct = self._get_text(self._cipher_in).strip()
        if not ct:
            messagebox.showwarning("Empty Input", "Please enter ciphertext to decrypt.")
            return
        self._set_status("Deriving key and decrypting...")
        self.update_idletasks()

        def run():
            try:
                pt = RubikCipher(key).decrypt(ct)
                self.after(0, self._set_text, self._plain_out, pt)
                self.after(0, self._set_status, "Decryption complete.")
            except Exception as exc:
                self.after(0, messagebox.showerror, "Decryption Error", str(exc))
                self.after(0, self._set_status, "Decryption failed.")

        threading.Thread(target=run, daemon=True).start()

    def _do_analysis(self):
        key = self._get_key()
        if key is None:
            return
        self._set_status("Running security analysis (avalanche + key sensitivity + speed)...")
        self.update_idletasks()

        def run():
            try:
                results = SecurityAnalyzer(key).run_all()
                self.after(0, self._display_analysis, results)
                self.after(0, self._set_status, "Analysis complete.")
            except Exception as exc:
                self.after(0, messagebox.showerror, "Analysis Error", str(exc))
                self.after(0, self._set_status, "Analysis failed.")

        threading.Thread(target=run, daemon=True).start()

    def _display_analysis(self, results: dict):
        av = results["avalanche"]
        ks = results["key_sensitivity"]
        sp = results["speed"]
        sep = "=" * 52

        ideal_note = "(ideal: ~50%)" if 40 <= av["avg_percentage"] <= 60 else "(below ideal ~50%)"

        report = f"""\
RUBIK Cipher v2 — Security Analysis Report
{sep}

AVALANCHE EFFECT
  Single-bit plaintext flip causes ciphertext change:
  Min bits changed  : {av['min_bits_changed']:>3} / 128
  Max bits changed  : {av['max_bits_changed']:>3} / 128
  Avg bits changed  : {av['avg_bits_changed']:>6.2f} / 128
  Avg change        : {av['avg_percentage']:>5.1f}%  {ideal_note}

KEY SENSITIVITY
  One-bit key difference → ciphertext divergence:
  Bits changed      : {ks['bits_changed']:>3} / 128  ({ks['percentage']:.1f}%)

PERFORMANCE  ({sp['data_size_kb']} KB sample)
  Encrypt speed     : {sp['encrypt_speed_kbps']:>8.1f} KB/s
  Decrypt speed     : {sp['decrypt_speed_kbps']:>8.1f} KB/s
  Encrypt time      : {sp['encrypt_time_s'] * 1000:>6.1f} ms
  Decrypt time      : {sp['decrypt_time_s'] * 1000:>6.1f} ms

ALGORITHM DETAILS
  Block size        : 128 bits (16 bytes)
  Rounds            : 8
  Key schedule      : PBKDF2-SHA256 (100 000 iterations)
  Mode              : CBC with random IV
  Padding           : PKCS#7
  S-Box             : Key-derived Fisher-Yates permutation
  MixColumns        : GF(2⁸) — same matrix as AES
{sep}
"""
        self._set_text(self._analysis_out, report)

    # ------------------------------------------------------------------ clipboard / paste

    def _copy_ciphertext(self):
        ct = self._get_text(self._cipher_out).strip()
        if ct:
            self.clipboard_clear()
            self.clipboard_append(ct)
            self._set_status("Ciphertext copied to clipboard.")
        else:
            self._set_status("Nothing to copy — encrypt something first.")

    def _paste_from_encrypt(self):
        ct = self._get_text(self._cipher_out).strip()
        if ct:
            self._cipher_in.config(state=tk.NORMAL)
            self._cipher_in.delete("1.0", tk.END)
            self._cipher_in.insert("1.0", ct)
            self._set_status("Ciphertext pasted into Decrypt tab.")
        else:
            self._set_status("Nothing to paste — encrypt something first.")

    def _clear_encrypt(self):
        self._plain_in.delete("1.0", tk.END)
        self._set_text(self._cipher_out, "")
        self._set_status("Encrypt tab cleared.")

    def _clear_decrypt(self):
        self._cipher_in.delete("1.0", tk.END)
        self._set_text(self._plain_out, "")
        self._set_status("Decrypt tab cleared.")
