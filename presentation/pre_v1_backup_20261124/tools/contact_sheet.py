#!/usr/bin/env python3
"""Tile page previews into one PNG for layout review: contact_sheet.py <first-page> <count> <out.png>.

Reads build/pages/p-*.png (written by `make pngs`), two pages per row.
"""
import glob
import sys

from PIL import Image

pages = sorted(glob.glob("build/pages/p-*.png"))
start, count, cols = int(sys.argv[1]), int(sys.argv[2]), 2
images = [Image.open(p) for p in pages[start - 1:start - 1 + count]]
w, h = images[0].size
rows = (len(images) + cols - 1) // cols
sheet = Image.new("RGB", (cols * w + (cols - 1) * 6, rows * h + (rows - 1) * 6), "red")
for i, im in enumerate(images):
    sheet.paste(im, ((i % cols) * (w + 6), (i // cols) * (h + 6)))
sheet.save(sys.argv[3])
