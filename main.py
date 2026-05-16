#!/usr/bin/env python3
"""Entry point — launches the RUBIK Cipher v2 GUI."""
from rubik_cipher_v2.gui.app import RubikCipherApp

if __name__ == "__main__":
    app = RubikCipherApp()
    app.mainloop()
