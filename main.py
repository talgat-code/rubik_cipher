#!/usr/bin/env python3
"""Entry point — launches the RUBIK Cipher v2 GUI."""
import tkinter as tk

from rubik_cipher_v2.gui.app import RubikCipherApp

if __name__ == "__main__":
    root = tk.Tk()
    app = RubikCipherApp(root)
    root.mainloop()
