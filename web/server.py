"""RUBIK Cipher v2 — FastAPI web server.

Usage:
    pip install fastapi "uvicorn[standard]" python-multipart
    python web/server.py          # http://127.0.0.1:8000
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import uvicorn
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from rubik_cipher_v2 import RubikCipher, SecurityAnalyzer

_STATIC = Path(__file__).parent / "static"
_TMP    = Path(tempfile.gettempdir())
_EXT    = ".rubik"

app = FastAPI(title="RUBIK Cipher v2", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=_STATIC), name="static")


def _cipher(key: str) -> RubikCipher:
    if not key.strip():
        raise HTTPException(422, "Ключ не может быть пустым.")
    return RubikCipher(key)


# ── Frontend ───────────────────────────────────────────────────────────────────

@app.get("/")
async def root() -> FileResponse:
    return FileResponse(_STATIC / "index.html")


# ── Text API ───────────────────────────────────────────────────────────────────

class TextBody(BaseModel):
    key: str
    text: str


@app.post("/api/encrypt")
async def api_encrypt(body: TextBody) -> dict:
    try:
        return {"result": _cipher(body.key).encrypt(body.text)}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, str(exc))


@app.post("/api/decrypt")
async def api_decrypt(body: TextBody) -> dict:
    try:
        return {"result": _cipher(body.key).decrypt(body.text.strip())}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, str(exc))


# ── File API ───────────────────────────────────────────────────────────────────

@app.post("/api/encrypt-file")
async def api_encrypt_file(key: str = Form(...), file: UploadFile = File(...)) -> FileResponse:
    try:
        cipher = _cipher(key)
        src = _TMP / f"rc2_src_{file.filename}"
        dst = _TMP / f"{file.filename}{_EXT}"
        src.write_bytes(await file.read())
        cipher.encrypt_file(str(src), str(dst))
        return FileResponse(str(dst), filename=f"{file.filename}{_EXT}",
                            media_type="application/octet-stream")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, str(exc))


@app.post("/api/decrypt-file")
async def api_decrypt_file(key: str = Form(...), file: UploadFile = File(...)) -> FileResponse:
    try:
        cipher = _cipher(key)
        fname  = file.filename or "file"
        out    = fname[: -len(_EXT)] if fname.endswith(_EXT) else f"dec_{fname}"
        src    = _TMP / f"rc2_src_{fname}"
        dst    = _TMP / f"rc2_dst_{out}"
        src.write_bytes(await file.read())
        cipher.decrypt_file(str(src), str(dst))
        return FileResponse(str(dst), filename=out, media_type="application/octet-stream")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, str(exc))


# ── Analysis API ───────────────────────────────────────────────────────────────

class AnalyzeBody(BaseModel):
    key: str = "demo-key"
    trials: int = 300
    size_kb: int = 5


@app.post("/api/analyze")
async def api_analyze(body: AnalyzeBody) -> dict:
    try:
        cipher = _cipher(body.key)
        az     = SecurityAnalyzer(cipher)
        return {
            "avalanche":  az.avalanche_test(n_trials=body.trials),
            "entropy":    az.frequency_analysis_test("A"),
            "key_space":  {str(k): v for k, v in az.key_space_report().items()},
            "benchmark":  az.benchmark(message_size_kb=body.size_kb),
            "comparison": az.compare_with_classics(),
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, str(exc))


if __name__ == "__main__":
    print("\n  RUBIK Cipher v2  →  http://127.0.0.1:8000\n")
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)
