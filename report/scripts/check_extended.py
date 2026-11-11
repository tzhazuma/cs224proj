import glob
import re

files = ["report/report_extended_zh.tex"] + glob.glob("report/extended_tables*.tex") + ["report/extended_numbers.tex"]
lines = []
for f in files:
    for line in open(f, encoding="utf-8"):
        lines.append(line.split("%")[0])
text = "\n".join(lines)

labels = set(re.findall(r"\\label\{([^}]+)\}", text))
refs = set(re.findall(r"\\(?:ref|eqref)\{([^}]+)\}", text))
cites = set()
for m in re.findall(r"\\cite\{([^}]+)\}", text):
    cites.update(x.strip() for x in m.split(","))
bib = open("report/references_extended.bib", encoding="utf-8").read()
keys = set(re.findall(r"@\w+\{([^,]+),", bib))
print("labels", len(labels), "refs", len(refs), "cites", len(cites), "bib", len(keys))
print("missing refs", sorted(refs - labels))
print("missing cites", sorted(cites - keys))
print("unused labels", len(labels - refs))
