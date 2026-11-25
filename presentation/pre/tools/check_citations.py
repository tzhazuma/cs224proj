#!/usr/bin/env python3
"""Check the numbered per-frame citations of main.pdf (see \\sref in main.tex).

Reads build/main.sref, written at shipout: "B <page> <n> <key>" for every superscript in the page body and
"F <page> <n> <key>" for every footer entry. Fails (exit 1) when, on any page,
  - a superscript has no footer entry or a footer entry has no superscript (sets of (n, key) differ),
  - one number maps to two keys, or numbers are not 1..k in order of first mention,
  - the footer box is taller than two lines ("H <page> <pt>" lines),
and when a section still uses the old \\slidecite macro.
"""
import collections, pathlib, re, sys

root = pathlib.Path(__file__).resolve().parent.parent
sref = root / "build" / "main.sref"
if not sref.exists():
    sys.exit("check_citations: build/main.sref missing (run make first)")
body, foot = collections.defaultdict(list), collections.defaultdict(list)
errors = []
MAX_FOOTER_PT = 19.0  # two 7.4 pt lines measure about 15.4 pt (height + depth), three about 23 pt
for line in sref.read_text().splitlines():
    if line.startswith("H "):
        _, page, height = line.split()
        if float(height) > MAX_FOOTER_PT:
            errors.append(f"p{page}: footer needs more than two lines ({height} pt); shorten entries or cite less")
        continue
    kind, page, n, key = line.split()
    (body if kind == "B" else foot)[page].append((int(n), key))
for page in sorted(set(body) | set(foot), key=int):
    b, f = body[page], foot[page]
    if set(b) != set(f):
        for n, k in sorted(set(b) - set(f)):
            errors.append(f"p{page}: superscript {n} ({k}) has no footer entry")
        for n, k in sorted(set(f) - set(b)):
            errors.append(f"p{page}: footer entry {n} ({k}) has no superscript")
    keys_by_n = collections.defaultdict(set)
    for n, k in b + f:
        keys_by_n[n].add(k)
    errors += [f"p{page}: number {n} used for {sorted(ks)}" for n, ks in keys_by_n.items() if len(ks) > 1]
    first = list(dict.fromkeys(n for n, _ in b))
    if first != list(range(1, len(first) + 1)):
        errors.append(f"p{page}: superscripts not numbered 1..k in order of first mention: {first}")
for tex in sorted((root / "sections").glob("*.tex")):
    for i, line in enumerate(tex.read_text().splitlines(), 1):
        if re.search(r"\\slidecite\b", line.split("%")[0]):
            errors.append(f"{tex.relative_to(root)}:{i}: old \\slidecite (use \\sref at the mention)")
pages = len(set(body) | set(foot))
n_cites = sum(len(v) for v in foot.values())
if errors:
    print("citations: MISMATCH")
    print("\n".join(errors))
    sys.exit(1)
print(f"citations: ok ({pages} pages with sources, {n_cites} footer entries, every entry has a superscript)")
