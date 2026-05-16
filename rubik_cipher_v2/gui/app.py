"""Tkinter GUI for RUBIK Cipher v2 — two-tab cipher + analysis interface."""
import os
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk

from ..core.cipher import RubikCipher
from ..analysis.security_analysis import SecurityAnalyzer

# ── Catppuccin Mocha colour palette ───────────────────────────────────────────
C: dict[str, str] = {
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

_TITLE      = "RUBIK Cipher v2 — Cryptography Project"
_GEOMETRY   = "740x620"
_MIN_SIZE   = (600, 500)
_RUBIK_EXT  = ".rubik"


class RubikCipherApp(tk.Frame):
    """Main application frame — embeds into any Tk root window."""

    def __init__(self, master: tk.Tk) -> None:
        """Build and pack the full GUI inside *master*.

        Args:
            master: Tkinter root window.
        """
        super().__init__(master, bg=C["base"])
        master.title(_TITLE)
        master.geometry(_GEOMETRY)
        master.minsize(*_MIN_SIZE)
        master.configure(bg=C["base"])
        self.pack(fill=tk.BOTH, expand=True)

        self._key_var = tk.StringVar()
        self._status_var = tk.StringVar(value="Ready")
        self._loaded_file: str | None = None

        self._build_ui()

    # ── top-level layout ──────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        """Assemble header, key row, notebook, and status bar."""
        self._build_header()
        self._build_key_row()
        self._build_notebook()
        self._build_statusbar()

    def _build_header(self) -> None:
        hdr = tk.Frame(self, bg=C["mantle"], pady=12)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="RUBIK Cipher v2", font=("Consolas", 17, "bold"),
                 bg=C["mantle"], fg=C["mauve"]).pack(side=tk.LEFT, padx=18)
        tk.Label(hdr, text="Cryptography Project  ·  CBC + PKCS7",
                 font=("Consolas", 9), bg=C["mantle"], fg=C["overlay0"]).pack(side=tk.LEFT)

    def _build_key_row(self) -> None:
        frame = tk.Frame(self, bg=C["base"], pady=10)
        frame.pack(fill=tk.X, padx=18)
        tk.Label(frame, text="Key:", font=("Consolas", 11),
                 bg=C["base"], fg=C["text"]).pack(side=tk.LEFT)
        self._key_entry = tk.Entry(
            frame, textvariable=self._key_var, font=("Consolas", 11),
            show="•", bg=C["surface0"], fg=C["text"],
            insertbackground=C["text"], relief=tk.FLAT, bd=0, width=34,
        )
        self._key_entry.pack(side=tk.LEFT, padx=(8, 0), ipady=5, ipadx=4)
        self._show_btn = tk.Button(
            frame, text="Show", font=("Consolas", 9),
            bg=C["surface1"], fg=C["text"], relief=tk.FLAT, bd=0,
            padx=10, cursor="hand2", command=self._toggle_key,
        )
        self._show_btn.pack(side=tk.LEFT, padx=6)

    def _build_notebook(self) -> None:
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("TNotebook", background=C["base"], borderwidth=0)
        style.configure("TNotebook.Tab", background=C["surface0"], foreground=C["text"],
                        font=("Consolas", 10), padding=[14, 6])
        style.map("TNotebook.Tab",
                  background=[("selected", C["mauve"])],
                  foreground=[("selected", C["mantle"])])
        style.configure("Ana.Horizontal.TProgressbar",
                        troughcolor=C["surface0"], background=C["mauve"])

        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=18, pady=(0, 4))

        cipher_tab = tk.Frame(nb, bg=C["base"])
        analysis_tab = tk.Frame(nb, bg=C["base"])
        nb.add(cipher_tab, text="   Cipher   ")
        nb.add(analysis_tab, text="   Analysis   ")

        self._build_cipher_tab(cipher_tab)
        self._build_analysis_tab(analysis_tab)

    def _build_statusbar(self) -> None:
        tk.Frame(self, bg=C["surface1"], height=1).pack(fill=tk.X, side=tk.BOTTOM)
        bar = tk.Frame(self, bg=C["mantle"], pady=5)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        self._status_lbl = tk.Label(bar, textvariable=self._status_var,
                                     font=("Consolas", 9), bg=C["mantle"],
                                     fg=C["green"], anchor=tk.W)
        self._status_lbl.pack(fill=tk.X, padx=14)

    # ── Tab 1: Cipher ─────────────────────────────────────────────────────────

    def _build_cipher_tab(self, parent: tk.Frame) -> None:
        tk.Label(parent, text="Input:", font=("Consolas", 10),
                 bg=C["base"], fg=C["text"]).pack(anchor=tk.W, padx=16, pady=(12, 2))
        self._input_text = scrolledtext.ScrolledText(
            parent, font=("Consolas", 10),
            bg=C["surface0"], fg=C["text"], insertbackground=C["text"],
            relief=tk.FLAT, bd=0, height=8, wrap=tk.WORD,
        )
        self._input_text.pack(fill=tk.BOTH, expand=True, padx=16)

        load_row = tk.Frame(parent, bg=C["base"], pady=4)
        load_row.pack(fill=tk.X, padx=16)
        self._file_label = tk.Label(load_row, text="", font=("Consolas", 8),
                                     bg=C["base"], fg=C["yellow"])
        self._file_label.pack(side=tk.LEFT)
        self._btn(load_row, "Load File", C["surface1"], C["text"],
                  self._load_file).pack(side=tk.RIGHT)

        btn_row = tk.Frame(parent, bg=C["base"], pady=6)
        btn_row.pack(fill=tk.X, padx=16)
        self._btn(btn_row, "  ENCRYPT  ", C["mauve"], C["mantle"],
                  self._do_encrypt).pack(side=tk.LEFT)
        self._btn(btn_row, "  DECRYPT  ", C["blue"], C["mantle"],
                  self._do_decrypt).pack(side=tk.LEFT, padx=14)

        tk.Label(parent, text="Output:", font=("Consolas", 10),
                 bg=C["base"], fg=C["text"]).pack(anchor=tk.W, padx=16, pady=(4, 2))
        self._output_text = scrolledtext.ScrolledText(
            parent, font=("Consolas", 10), bg=C["mantle"], fg=C["green"],
            relief=tk.FLAT, bd=0, height=7, wrap=tk.WORD, state=tk.DISABLED,
        )
        self._output_text.pack(fill=tk.BOTH, expand=True, padx=16)

        copy_row = tk.Frame(parent, bg=C["base"], pady=6)
        copy_row.pack(fill=tk.X, padx=16)
        self._btn(copy_row, "Copy", C["surface1"], C["text"],
                  self._copy_output).pack(side=tk.LEFT)
        self._btn(copy_row, "Save File", C["surface1"], C["text"],
                  self._save_file).pack(side=tk.LEFT, padx=8)

    # ── Tab 2: Analysis ───────────────────────────────────────────────────────

    def _build_analysis_tab(self, parent: tk.Frame) -> None:
        ctrl = tk.Frame(parent, bg=C["base"], pady=12)
        ctrl.pack(fill=tk.X, padx=16)
        self._btn(ctrl, "Run All Tests", C["red"], C["mantle"],
                  self._run_analysis).pack(side=tk.LEFT)
        self._progress = ttk.Progressbar(ctrl, mode="indeterminate", length=160,
                                          style="Ana.Horizontal.TProgressbar")
        self._progress.pack(side=tk.LEFT, padx=14)

        metrics = tk.Frame(parent, bg=C["surface0"], pady=10)
        metrics.pack(fill=tk.X, padx=16)
        self._av_lbl  = self._metric_row(metrics, "Avalanche effect:", "—")
        self._ks_lbl  = self._metric_row(metrics, "Key space (16ch):", "—")
        self._en_lbl  = self._metric_row(metrics, "Freq. entropy:",    "—")
        self._sp_lbl  = self._metric_row(metrics, "Encrypt speed:",    "—")

        tk.Label(parent, text="Comparison table:", font=("Consolas", 10),
                 bg=C["base"], fg=C["text"]).pack(anchor=tk.W, padx=16, pady=(10, 2))
        self._cmp_text = scrolledtext.ScrolledText(
            parent, font=("Consolas", 9), bg=C["mantle"], fg=C["text"],
            relief=tk.FLAT, bd=0, state=tk.DISABLED, wrap=tk.NONE,
        )
        self._cmp_text.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 10))

    # ── widget helpers ────────────────────────────────────────────────────────

    def _btn(self, parent: tk.Widget, text: str, bg: str, fg: str,
             cmd) -> tk.Button:
        """Create and return a flat-style button."""
        return tk.Button(parent, text=text, font=("Consolas", 10, "bold"),
                         bg=bg, fg=fg, relief=tk.FLAT, bd=0,
                         padx=12, pady=5, cursor="hand2", command=cmd)

    def _metric_row(self, parent: tk.Frame, label: str, value: str) -> tk.Label:
        """Add a label-value row to the metrics panel and return the value label."""
        row = tk.Frame(parent, bg=C["surface0"])
        row.pack(fill=tk.X, padx=12, pady=2)
        tk.Label(row, text=label, font=("Consolas", 10), width=20, anchor=tk.W,
                 bg=C["surface0"], fg=C["overlay0"]).pack(side=tk.LEFT)
        lbl = tk.Label(row, text=value, font=("Consolas", 10),
                       bg=C["surface0"], fg=C["text"])
        lbl.pack(side=tk.LEFT)
        return lbl

    def _set_text(self, widget: scrolledtext.ScrolledText, text: str) -> None:
        """Replace all text in a read-only ScrolledText widget."""
        widget.config(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert("1.0", text)
        widget.config(state=tk.DISABLED)

    def _set_status(self, msg: str, error: bool = False) -> None:
        """Update the status bar text and colour."""
        self._status_var.set(msg)
        self._status_lbl.config(fg=C["red"] if error else C["green"])

    def _get_key(self) -> str | None:
        """Return the entered key, or None after showing an error."""
        key = self._key_var.get().strip()
        if not key:
            self._set_status("Error: Please enter a key.", error=True)
            return None
        return key

    # ── key visibility toggle ─────────────────────────────────────────────────

    def _toggle_key(self) -> None:
        """Toggle the key entry between masked (•) and plaintext display."""
        if self._key_entry.cget("show") == "•":
            self._key_entry.config(show="")
            self._show_btn.config(text="Hide")
        else:
            self._key_entry.config(show="•")
            self._show_btn.config(text="Show")

    # ── file I/O ──────────────────────────────────────────────────────────────

    def _load_file(self) -> None:
        """Open a file-chooser and load the selected file into the input area."""
        path = filedialog.askopenfilename(title="Select file")
        if not path:
            return
        self._loaded_file = path
        name = os.path.basename(path)
        self._input_text.delete("1.0", tk.END)
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._input_text.insert("1.0", f.read())
            self._file_label.config(text=f"[text: {name}]")
            self._set_status(f"Loaded: {name}")
        except UnicodeDecodeError:
            self._input_text.insert("1.0", f"[binary file: {name}]")
            self._file_label.config(text=f"[binary: {name}]")
            self._set_status(f"Binary file ready: {name}")

    def _save_file(self) -> None:
        """Save the output area content to a user-chosen file."""
        text = self._output_text.get("1.0", tk.END).strip()
        if not text or text.startswith("["):
            self._set_status("Nothing to save.", error=True)
            return
        path = filedialog.asksaveasfilename(title="Save output")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            self._set_status(f"Saved: {path}")

    # ── encrypt / decrypt ─────────────────────────────────────────────────────

    def _get_input_text(self) -> str:
        """Return the current text-area content with trailing newline stripped."""
        return self._input_text.get("1.0", tk.END).rstrip("\n")

    def _do_encrypt(self) -> None:
        """Encrypt the input area contents (or loaded binary file) in a thread."""
        key = self._get_key()
        if key is None:
            return
        self._set_status("Deriving key and encrypting…")
        self.update_idletasks()

        def run() -> None:
            try:
                cipher = RubikCipher(key)
                loaded = self._loaded_file
                is_binary_file = False
                if loaded and not loaded.endswith(_RUBIK_EXT):
                    try:
                        with open(loaded, "rb") as fh:
                            is_binary_file = b"\x00" in fh.read(512)
                    except Exception:
                        pass
                if is_binary_file and loaded:
                    out = loaded + _RUBIK_EXT
                    cipher.encrypt_file(loaded, out)
                    result = f"[Encrypted → {out}]"
                else:
                    result = cipher.encrypt(self._get_input_text())
                self.after(0, self._set_text, self._output_text, result)
                self.after(0, self._set_status, "Encryption complete.")
            except Exception as exc:
                self.after(0, self._set_status, f"Error: {exc}", True)

        threading.Thread(target=run, daemon=True).start()

    def _do_decrypt(self) -> None:
        """Decrypt the input area contents (or loaded .rubik file) in a thread."""
        key = self._get_key()
        if key is None:
            return
        self._set_status("Deriving key and decrypting…")
        self.update_idletasks()

        def run() -> None:
            try:
                cipher = RubikCipher(key)
                loaded = self._loaded_file
                if loaded and loaded.endswith(_RUBIK_EXT):
                    out = loaded[: -len(_RUBIK_EXT)]
                    cipher.decrypt_file(loaded, out)
                    result = f"[Decrypted → {out}]"
                else:
                    result = cipher.decrypt(self._get_input_text().strip())
                self.after(0, self._set_text, self._output_text, result)
                self.after(0, self._set_status, "Decryption complete.")
            except Exception as exc:
                self.after(0, self._set_status, f"Error: {exc}", True)

        threading.Thread(target=run, daemon=True).start()

    def _copy_output(self) -> None:
        """Copy the output area text to the system clipboard."""
        text = self._output_text.get("1.0", tk.END).strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self._set_status("Output copied to clipboard.")
        else:
            self._set_status("Nothing to copy.", error=True)

    # ── analysis ──────────────────────────────────────────────────────────────

    def _run_analysis(self) -> None:
        """Launch all security tests in a background thread."""
        key = self._get_key()
        if key is None:
            return
        self._progress.start(10)
        self._set_status("Running security analysis…")

        def run() -> None:
            try:
                cipher = RubikCipher(key)
                az = SecurityAnalyzer(cipher)
                av    = az.avalanche_test(n_trials=200)
                ks    = az.key_space_report()
                freq  = az.frequency_analysis_test("A")
                bench = az.benchmark(message_size_kb=5)
                table = az.compare_with_classics()
                self.after(0, self._display_metrics, av, ks, freq, bench)
                self.after(0, self._set_text, self._cmp_text, table)
                self.after(0, self._set_status, "Analysis complete.")
            except Exception as exc:
                self.after(0, self._set_status, f"Analysis error: {exc}", True)
            finally:
                self.after(0, self._progress.stop)

        threading.Thread(target=run, daemon=True).start()

    def _display_metrics(self, av: dict, ks: dict, freq: dict, bench: dict) -> None:
        """Populate the metric labels after analysis completes."""
        pct = av["avg_pct"]
        filled = round(pct / 100 * 20)
        bar = "█" * filled + "░" * (20 - filled)
        self._av_lbl.config(text=f"{bar}  {pct:.1f}%  (min {av['min']}, max {av['max']})")

        combos = ks[16]["combinations"]
        bits   = ks[16]["bit_security"]
        exp    = len(str(combos)) - 1
        mant   = combos / 10 ** exp
        self._ks_lbl.config(text=f"{mant:.1f} × 10^{exp}  ({bits:.0f} bits)")

        self._en_lbl.config(text=f"{freq['entropy_score']:.2f} / 8.0 bits  "
                                  f"({freq['unique_bytes']} unique bytes)")

        ms_per_kb = bench["encrypt_ms"] / bench["message_size_kb"]
        self._sp_lbl.config(text=f"{ms_per_kb:.1f} ms/KB  "
                                  f"({bench['encrypt_kbps']:.0f} KB/s)")
