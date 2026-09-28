"""
Builds kaggle/phishing-analyser-bundle.zip from kaggle/bundle/.

Uses Python's zipfile rather than PowerShell 5.1's Compress-Archive, which writes Windows backslashes into entry
names ("ml\\translate.py") - invalid per the zip spec, and rejected by Kaggle. Entries here always use "/".
The trainer binary keeps its Unix executable bit.
"""
import os
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "bundle"
OUT = HERE / "phishing-analyser-bundle.zip"

OUT.unlink(missing_ok=True)
count = 0
with zipfile.ZipFile(OUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
    for path in sorted(SRC.rglob("*")):
        if path.is_dir():
            continue
        name = path.relative_to(SRC).as_posix()          # forward slashes, always
        info = zipfile.ZipInfo.from_file(path, name)
        executable = name == "trainer/PhishingAnalyser.Trainer" or name.endswith("/createdump")
        info.external_attr = (0o100755 if executable else 0o100644) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        with open(path, "rb") as fh:
            zf.writestr(info, fh.read())
        count += 1

with zipfile.ZipFile(OUT) as zf:
    bad = [n for n in zf.namelist() if "\\" in n]
print(f"{OUT.name}: {count} files, {OUT.stat().st_size / 1e6:.0f} MB, entries with backslashes: {len(bad)}")
