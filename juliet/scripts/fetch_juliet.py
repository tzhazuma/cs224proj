#!/usr/bin/env python3
"""Download the official NIST SARD Juliet C/C++ v1.3 suite and extract CWE-401.

Only the Python standard library is used. The archive is kept in
``juliet/cache/`` for provenance; the CWE-401 test cases and their support
library are extracted to ``juliet/raw/``.  ``provenance.json`` records the
URL, response headers, size and SHA-256 of both the archive and every
extracted file.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import shutil
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_URL = (
    "https://samate.nist.gov/SARD/downloads/test-suites/"
    "2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"
)
CWE_DIR = "testcases/CWE401_Memory_Leak"
SUPPORT_DIR = "testcasesupport"


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def head_metadata(url: str) -> dict:
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "cs224proj-juliet-fetch/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return {
                "url": resp.geturl(),
                "status": resp.status,
                "content_type": resp.headers.get("Content-Type"),
                "content_length": resp.headers.get("Content-Length"),
                "last_modified": resp.headers.get("Last-Modified"),
                "etag": resp.headers.get("ETag"),
            }
    except (urllib.error.URLError, OSError) as exc:
        return {"url": url, "head_error": str(exc)}


def download(url: str, dest: Path, retries: int = 3) -> dict:
    dest.parent.mkdir(parents=True, exist_ok=True)
    headers = {
        "User-Agent": "cs224proj-juliet-fetch/1.0 (+academic benchmark)",
        "Accept": "application/zip,application/octet-stream;q=0.9,*/*;q=0.8",
    }
    last_error = None
    for attempt in range(1, retries + 1):
        tmp = dest.with_suffix(dest.suffix + ".part")
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as resp:
                meta = {
                    "url": resp.geturl(),
                    "status": resp.status,
                    "content_type": resp.headers.get("Content-Type"),
                    "content_length": resp.headers.get("Content-Length"),
                    "last_modified": resp.headers.get("Last-Modified"),
                    "etag": resp.headers.get("ETag"),
                    "downloaded_at_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                }
                total = int(resp.headers.get("Content-Length") or 0)
                written = 0
                started = time.time()
                with tmp.open("wb") as out:
                    while True:
                        block = resp.read(1 << 20)
                        if not block:
                            break
                        out.write(block)
                        written += len(block)
                        if total and written % (20 << 20) < (1 << 20):
                            pct = 100.0 * written / total
                            print(f"  {written/1e6:.1f}/{total/1e6:.1f} MB ({pct:.1f}%)", flush=True)
                elapsed = max(time.time() - started, 1e-6)
            if total and written != total:
                raise IOError(f"short download: {written} of {total} bytes")
            tmp.replace(dest)
            meta["bytes"] = written
            meta["sha256"] = sha256_file(dest)
            meta["elapsed_seconds"] = round(elapsed, 2)
            meta["attempt"] = attempt
            return meta
        except (urllib.error.URLError, OSError, IOError) as exc:
            last_error = exc
            print(f"  attempt {attempt}/{retries} failed: {exc}", file=sys.stderr, flush=True)
            if tmp.exists():
                tmp.unlink()
            time.sleep(3 * attempt)
    raise SystemExit(f"download failed after {retries} attempts: {last_error}")


def extract(archive: Path, raw_root: Path, force: bool) -> dict:
    extracted = []
    with zipfile.ZipFile(archive) as zf:
        bad = zf.testzip()
        if bad is not None:
            raise SystemExit(f"zip integrity failure at member: {bad}")
        names = zf.namelist()
        # The v1.3 archive has a single top-level directory. Detect it rather
        # than hard-coding it so the script also works with fresh SARD builds.
        candidates = sorted(
            {n.split("/", 1)[0] for n in names if "/" in n and n.endswith(".c")}
        )
        prefix = candidates[0] + "/" if len(candidates) == 1 else ""
        wanted = [n for n in names if n.startswith(prefix + CWE_DIR + "/")]
        wanted += [n for n in names if n.startswith(prefix + SUPPORT_DIR + "/")]
        wanted += [n for n in names if n.startswith(prefix + "doc/")]
        wanted += [n for n in names if n == prefix + "Makefile"]
        if not any(n.endswith(".c") or n.endswith(".cpp") for n in wanted):
            raise SystemExit("no CWE-401 sources found in archive")
        if force and raw_root.exists():
            shutil.rmtree(raw_root)
        raw_root.mkdir(parents=True, exist_ok=True)
        for member in wanted:
            if member.endswith("/"):
                continue
            rel = member[len(prefix):]
            target = raw_root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
            extracted.append(rel)
    extracted.sort()
    return {"member_prefix": prefix, "files": extracted}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--redownload", action="store_true", help="discard and download the archive again")
    ap.add_argument("--force", action="store_true", help="re-extract even if raw/ exists")
    args = ap.parse_args()

    cache = ROOT / "cache" / "juliet-c-cplusplus-v1.3.zip"
    raw = ROOT / "raw"
    provenance_path = ROOT / "provenance.json"

    if cache.exists() and not args.redownload:
        print(f"archive exists, reusing: {cache}")
        meta = head_metadata(DEFAULT_URL)
        meta["reused_existing"] = True
        meta["bytes"] = cache.stat().st_size
        meta["sha256"] = sha256_file(cache)
    else:
        print(f"downloading {args.url}")
        meta = download(args.url, cache)
        print(f"  saved {meta['bytes']} bytes sha256={meta['sha256']}")

    print("extracting CWE-401 + testcasesupport")
    ext = extract(cache, raw, force=args.force)
    per_file = {}
    for rel in ext["files"]:
        p = raw / rel
        per_file[rel] = {"sha256": sha256_file(p), "bytes": p.stat().st_size}

    doc = {
        "dataset": "Juliet Test Suite for C/C++ v1.3 (CWE-401 subset)",
        "cwe": 401,
        "archive": meta,
        "extraction": {
            "member_prefix": ext["member_prefix"],
            "cwe_dir": CWE_DIR,
            "support_dir": SUPPORT_DIR,
            "file_count": len(per_file),
            "extracted_at_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        },
        "files": per_file,
    }
    provenance_path.write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {provenance_path} ({len(per_file)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
