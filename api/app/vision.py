"""
Thai Cyber Shield API - secure image ingestion, OCR & QR pipeline.

Pipeline for an uploaded screenshot (chat or transfer slip):

  1. Byte-level gate   : size cap, magic-byte allow-list (PNG / JPEG / WebP).
                         The client's Content-Type and filename are ignored.
  2. Decoder hardening : Pillow decompression-bomb guard (MAX_IMAGE_PIXELS),
                         verify() pass, dimension cap, first frame only.
  3. Forensic facts    : editing-software traces in EXIF / XMP / PNG text
                         chunks (Photoshop, PicsArt, Canva, Snapseed...).
  4. Re-encode         : EXIF orientation applied, converted to a fresh
                         grayscale PNG with NO metadata - only these clean
                         pixels ever reach the OCR process.
  5. QR decode         : pyzbar on the decoded pixel buffer (multiple scales).
  6. OCR               : Tesseract (Thai + English) as a separate process:
                         argv list (no shell), image via stdin, empty env,
                         prlimit caps (CPU, memory, files, no core dumps),
                         wall-clock timeout, bounded output, semaphore.
  7. Consistency check : glyph-height statistics of numeric words from the
                         Tesseract TSV - an edited amount pasted in another
                         font/size stands out (weak signal, low weight).
"""
from __future__ import annotations

import asyncio
import io
import logging
import os
import signal
import statistics
import warnings
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from PIL import Image, ImageOps, UnidentifiedImageError

from .config import Settings

log = logging.getLogger("tcs.vision")

# Treat Pillow's decompression-bomb WARNING as an error too (default only
# errors at 2x the limit).
warnings.simplefilter("error", Image.DecompressionBombWarning)

_EDIT_TOOLS = (
    "photoshop", "gimp", "picsart", "snapseed", "canva", "lightroom", "pixlr",
    "meitu", "polarr", "fotor", "inshot", "ibis", "affinity", "paint.net",
    "photopea", "remini", "facetune", "illustrator", "procreate",
)
_SAFE_ENV = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin",
             "OMP_THREAD_LIMIT": "1"}
MAX_OCR_OUTPUT = 512 * 1024


class ImageRejected(ValueError):
    """Raised with a short constant code safe to show to the client."""


class OcrUnavailable(RuntimeError):
    pass


@dataclass
class OcrWord:
    text: str
    conf: float
    height: int
    line_key: Tuple[int, int, int]


@dataclass
class VisionResult:
    text: str = ""
    mean_conf: int = 0
    qr_payloads: List[str] = field(default_factory=list)
    edited_by: Optional[str] = None
    words: List[OcrWord] = field(default_factory=list)
    width: int = 0
    height: int = 0


# ---------------------------------------------------------------------------
# 1-4: validation, forensics, re-encode
# ---------------------------------------------------------------------------
def _sniff(data: bytes) -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "WEBP"
    raise ImageRejected("UNSUPPORTED_IMAGE_TYPE")


def _metadata_strings(img: Image.Image) -> List[str]:
    out: List[str] = []
    try:
        exif = img.getexif()
        for tag in (0x0131, 0x000B, 0x013B, 0x9286):   # Software, ProcessingSoftware, Artist, UserComment
            v = exif.get(tag)
            if isinstance(v, bytes):
                v = v.decode("latin-1", "replace")
            if isinstance(v, str):
                out.append(v[:200])
    except Exception:  # malformed EXIF must never break the pipeline
        pass
    for key, v in list(img.info.items())[:40]:
        if isinstance(v, (str, bytes)) and str(key).lower() in {
            "software", "comment", "description", "xmp", "xml:com.adobe.xmp", "creator",
        }:
            s = v.decode("latin-1", "replace") if isinstance(v, bytes) else v
            out.append(s[:4000])
    return out


def load_image(data: bytes, settings: Settings) -> Tuple[Image.Image, Optional[str]]:
    if not data:
        raise ImageRejected("EMPTY_FILE")
    if len(data) > settings.max_upload_bytes:
        raise ImageRejected("IMAGE_TOO_LARGE")
    fmt = _sniff(data)

    Image.MAX_IMAGE_PIXELS = settings.max_image_pixels      # bomb guard (raises)
    try:
        with Image.open(io.BytesIO(data)) as probe:
            if probe.format != fmt:
                raise ImageRejected("IMAGE_TYPE_MISMATCH")
            probe.verify()                                   # structural check
        img = Image.open(io.BytesIO(data))
        img.seek(0)                                          # first frame only
        w, h = img.size
        if w < 50 or h < 50 or w > 8000 or h > 8000:
            raise ImageRejected("IMAGE_DIMENSIONS")
        img.load()
    except ImageRejected:
        raise
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise ImageRejected("IMAGE_TOO_LARGE") from None
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError):
        raise ImageRejected("IMAGE_CORRUPT") from None

    edited_by = None
    blob = " ".join(_metadata_strings(img)).lower()
    for tool in _EDIT_TOOLS:
        if tool in blob:
            edited_by = tool
            break

    img = ImageOps.exif_transpose(img)
    img = img.convert("RGB")                                 # drops alpha/palette tricks
    return img, edited_by


def _ocr_ready(img: Image.Image) -> bytes:
    """Grayscale, scaled for Tesseract, re-encoded PNG without metadata."""
    g = img.convert("L")
    w, h = g.size
    scale = 1.0
    if w < 1000:
        scale = min(3.0, 1000 / w)
    elif w > 2400:
        scale = 2400 / w
    if scale != 1.0:
        g = g.resize((int(w * scale), int(h * scale)), Image.LANCZOS)
    g = ImageOps.autocontrast(g)
    buf = io.BytesIO()
    g.save(buf, format="PNG", optimize=False)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# 5: QR
# ---------------------------------------------------------------------------
def decode_qr(img: Image.Image) -> List[str]:
    try:
        from pyzbar.pyzbar import ZBarSymbol, decode
    except Exception:                                  # libzbar missing
        log.warning("pyzbar/libzbar not available - QR decoding disabled")
        return []
    payloads: List[str] = []
    candidates = [img.convert("L")]
    w, h = img.size
    if w < 1400:
        candidates.append(img.convert("L").resize((w * 2, h * 2), Image.NEAREST))
    for cand in candidates:
        try:
            for sym in decode(cand, symbols=[ZBarSymbol.QRCODE]):
                raw = sym.data[:600]
                try:
                    s = raw.decode("ascii")
                except UnicodeDecodeError:
                    continue
                if s.isprintable() and s not in payloads:
                    payloads.append(s)
        except Exception:
            continue
        if payloads:
            break
    return payloads[:4]


# ---------------------------------------------------------------------------
# 6: OCR in a sandboxed subprocess
# ---------------------------------------------------------------------------
class OcrRunner:
    def __init__(self, settings: Settings) -> None:
        self._s = settings
        self._sem = asyncio.Semaphore(settings.ocr_max_concurrency)
        path = settings.tesseract_path
        self.available = os.path.isabs(path) and os.path.isfile(path) and os.access(path, os.X_OK)
        if not self.available:
            log.warning("tesseract not found at %s - OCR disabled", path)

    def _argv(self) -> List[str]:
        argv = [self._s.tesseract_path, "stdin", "stdout", "-l", self._s.ocr_langs,
                "--psm", "6", "--oem", "1", "tsv"]
        if self._s.engine_use_prlimit:
            argv = [self._s.prlimit_path, "--cpu=40", "--as=1610612736",
                    "--nofile=64", "--fsize=0", "--core=0", "--", *argv]
        return argv

    async def run(self, png: bytes) -> str:
        if not self.available:
            raise OcrUnavailable("OCR_UNAVAILABLE")
        try:
            await asyncio.wait_for(self._sem.acquire(), timeout=15.0)
        except asyncio.TimeoutError:
            raise OcrUnavailable("OCR_BUSY") from None
        try:
            proc = await asyncio.create_subprocess_exec(
                *self._argv(),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                env=_SAFE_ENV, cwd="/", close_fds=True, start_new_session=True,
            )

            async def exchange() -> bytes:
                assert proc.stdin and proc.stdout
                try:
                    proc.stdin.write(png)
                    await proc.stdin.drain()
                except (BrokenPipeError, ConnectionResetError):
                    pass
                finally:
                    proc.stdin.close()
                chunks, total = [], 0
                while True:
                    chunk = await proc.stdout.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_OCR_OUTPUT:
                        raise OcrUnavailable("OCR_OUTPUT_TOO_LARGE")
                    chunks.append(chunk)
                await proc.wait()
                return b"".join(chunks)

            try:
                out = await asyncio.wait_for(exchange(), timeout=self._s.ocr_timeout_s)
            except (asyncio.TimeoutError, OcrUnavailable):
                raise OcrUnavailable("OCR_TIMEOUT") from None
            finally:
                if proc.returncode is None:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=2.0)
                    except asyncio.TimeoutError:
                        pass
            if proc.returncode != 0:
                raise OcrUnavailable("OCR_FAILED")
            return out.decode("utf-8", "replace")
        finally:
            self._sem.release()


def parse_tsv(tsv: str) -> Tuple[str, int, List[OcrWord]]:
    """Rebuild reading-order text from Tesseract TSV; return (text, mean
    confidence, words)."""
    lines: dict = {}
    words: List[OcrWord] = []
    confs: List[float] = []
    for row in tsv.splitlines()[1:20000]:
        cols = row.split("\t")
        if len(cols) != 12 or cols[0] != "5":
            continue
        text = cols[11].strip()
        if not text:
            continue
        try:
            conf = float(cols[10])
            height = int(cols[9])
            key = (int(cols[2]), int(cols[3]), int(cols[4]))
        except ValueError:
            continue
        if conf >= 0:
            confs.append(conf)
        words.append(OcrWord(text=text[:200], conf=conf, height=height, line_key=key))
        lines.setdefault(key, []).append(text[:200])
    ordered = [" ".join(lines[k]) for k in sorted(lines)]
    mean = int(sum(confs) / len(confs)) if confs else 0
    return "\n".join(ordered)[:12000], max(0, min(100, mean)), words


# ---------------------------------------------------------------------------
# 7: glyph-height consistency of numeric words (edited-amount heuristic)
# ---------------------------------------------------------------------------
def numeric_inconsistency(words: List[OcrWord], amount_text: Optional[str]) -> bool:
    if not amount_text:
        return False
    target = amount_text.replace(",", "")
    numeric = [w for w in words if sum(c.isdigit() for c in w.text) >= 2 and w.height > 0]
    amount_words = [w for w in numeric if target and target in w.text.replace(",", "")]
    others = [w for w in numeric if w not in amount_words]
    if not amount_words or len(others) < 4:
        return False
    med_h = statistics.median(w.height for w in others)
    med_c = statistics.median(w.conf for w in others if w.conf >= 0) if others else 0
    a = amount_words[0]
    # The amount is normally the LARGEST text on a slip, so only a smaller-
    # than-body amount or a very low confidence relative to its neighbours
    # is treated as suspicious.
    too_small = a.height < 0.75 * med_h
    conf_gap = a.conf >= 0 and med_c - a.conf > 35
    return too_small or conf_gap


async def analyse_image(data: bytes, settings: Settings, ocr: OcrRunner) -> VisionResult:
    img, edited_by = await asyncio.to_thread(load_image, data, settings)
    qr = await asyncio.to_thread(decode_qr, img)
    png = await asyncio.to_thread(_ocr_ready, img)
    tsv = await ocr.run(png)
    text, conf, words = parse_tsv(tsv)
    return VisionResult(text=text, mean_conf=conf, qr_payloads=qr, edited_by=edited_by,
                        words=words, width=img.size[0], height=img.size[1])
