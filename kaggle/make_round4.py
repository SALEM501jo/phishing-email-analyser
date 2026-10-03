"""
Round 4: the same recipe as the shipped round 1, retrained on a split that keeps each phishing CAMPAIGN on one side.

The evaluation audit found that the subject-only split let about 18% of test phishing have a near-copy in training
(recall on unseen campaigns was 74.9% against 79.5% overall). The trainer now groups near-duplicate bodies before
splitting (tools/PhishingAnalyser.Trainer/Corpus/NearDuplicates.cs). The data is prepared locally:

    dotnet run --project tools/PhishingAnalyser.Trainer -c Release -- --export-corpus
    dotnet run --project tools/PhishingAnalyser.Trainer -c Release -- --prepare-transformer data/processed --generators qwen2.5:7b-instruct

so Kaggle only trains. This script writes kaggle/phishing-round4-bundle.zip (the training script + the three prepared
files) and kaggle/phishing-transformer-round4.ipynb.
"""
import json
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BUNDLE = HERE / "phishing-round4-bundle.zip"

files = {
    "ml/train_transformer.py": ROOT / "ml" / "train_transformer.py",
    "ml/requirements.txt": ROOT / "ml" / "requirements.txt",
    **{f"data/processed/transformer_{s}.jsonl": ROOT / "data" / "processed" / f"transformer_{s}.jsonl" for s in ("train", "val", "test")},
}
BUNDLE.unlink(missing_ok=True)
with zipfile.ZipFile(BUNDLE, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
    for name, path in files.items():
        zf.write(path, name)  # forward-slash entry names (Kaggle rejects backslashes)
print(f"{BUNDLE.name}: {len(files)} files, {BUNDLE.stat().st_size / 1e6:.0f} MB")

cells = [
    ("markdown", """# Phishing Email Analyser - round 4: campaign-aware split

Same recipe as the shipped round 1 (public corpora + NLLB Arabic translations + 1,199 Qwen 2.5 7B pairs), retrained on
a split that keeps every phishing campaign - the same text under different subjects - on ONE side. The data arrives
already normalised and split by the .NET trainer, so this notebook only trains.

**Settings:** Accelerator **GPU T4 x2** · Internet **On** · attach the dataset `phishing-round4-bundle`. **Run All**,
then download `results.zip` from the Output tab."""),
    ("code", """# 1. Unpack the bundle (Kaggle keeps an uploaded zip either unpacked or as a .zip - handle both)
import glob, os, shutil, zipfile
PROJECT = '/kaggle/working/project'
if not os.path.exists(f'{PROJECT}/ml/train_transformer.py'):
    unpacked = glob.glob('/kaggle/input/**/ml/train_transformer.py', recursive=True)
    zips = glob.glob('/kaggle/input/**/*.zip', recursive=True)
    if unpacked:
        shutil.copytree(os.path.dirname(os.path.dirname(unpacked[0])), PROJECT, dirs_exist_ok=True)
    elif zips:
        with zipfile.ZipFile(zips[0]) as z:
            z.extractall(PROJECT)
    else:
        raise FileNotFoundError('Attach the phishing-round4-bundle dataset (right panel > Add Input)')
os.chdir(PROJECT)
os.environ.update(ML_THERMAL_GUARD='off', PYTHONUNBUFFERED='1')
!pip install -q transformers==4.46.3 onnx==1.17.0 onnxruntime==1.20.1 accelerate==1.1.1
!nvidia-smi --query-gpu=name,memory.total --format=csv
!wc -l data/processed/*.jsonl"""),
    ("code", """# 2. Fine-tune (3 epochs, same settings as round 1), export int8 ONNX + parity fixtures (~45 min)
!python ml/train_transformer.py --base distilbert/distilbert-base-multilingual-cased --epochs 3 --batch 32"""),
    ("code", """# 3. Package for download (Output tab -> results.zip)
!cd /kaggle/working/project && zip -qr /kaggle/working/results.zip models/transformer models/transformer-metrics.json
!ls -la /kaggle/working/results.zip
!head -60 models/transformer-metrics.json"""),
]
notebook = {
    "nbformat": 4, "nbformat_minor": 5,
    "metadata": {"kernelspec": {"name": "python3", "display_name": "Python 3", "language": "python"}, "language_info": {"name": "python"}},
    "cells": [{"cell_type": kind, "metadata": {}, "source": text.splitlines(keepends=True),
               **({"outputs": [], "execution_count": None} if kind == "code" else {})} for kind, text in cells],
}
out = HERE / "phishing-transformer-round4.ipynb"
out.write_text(json.dumps(notebook, indent=1), encoding="utf-8")
print("wrote", out.name)
