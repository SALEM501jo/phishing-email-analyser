"""Writes kaggle/phishing-transformer.ipynb - the cloud-GPU half of the ML pipeline (see kaggle/README.md)."""
import json
from pathlib import Path

cells = [
    ("markdown", """# Phishing Email Analyser: multilingual transformer (English + Arabic)

Runs the GPU-heavy steps on Kaggle's free GPU, because the owner's laptop GPU crashes under sustained load
(`VIDEO_TDR_FAILURE`). Everything else (the API, the .NET inference, the evaluation) stays in the repo.

**Settings (right panel):** Accelerator **GPU T4 x2** (or P100) · Internet **On** · attach the dataset
`phishing-analyser-bundle`. Then **Run All**. Download `results.zip` from the Output tab at the end.

Every step is resumable. If the session ends early, run again and it continues."""),

    ("code", """# 1. Copy the bundle to a writable project folder, install the pinned tooling
# Kaggle sometimes unpacks an uploaded zip into folders and sometimes keeps it as one .zip file - handle both.
import glob, os, shutil, subprocess, zipfile
PROJECT = '/kaggle/working/project'
print('input files:', [p for p in glob.glob('/kaggle/input/**', recursive=True) if os.path.isfile(p)][:10])
if not os.path.exists(f'{PROJECT}/trainer/PhishingAnalyser.Trainer'):
    unpacked = glob.glob('/kaggle/input/**/trainer/PhishingAnalyser.Trainer', recursive=True)
    zips = glob.glob('/kaggle/input/**/*.zip', recursive=True)
    if unpacked:
        shutil.copytree(os.path.dirname(os.path.dirname(unpacked[0])), PROJECT, dirs_exist_ok=True)
    elif zips:
        with zipfile.ZipFile(zips[0]) as z:
            z.extractall(PROJECT)
    else:
        raise FileNotFoundError('Bundle not found - attach the phishing-analyser-bundle dataset (right panel > Add Input)')
os.chmod(f'{PROJECT}/trainer/PhishingAnalyser.Trainer', 0o755)
os.chdir(PROJECT)

# Resume: if an earlier run's output is attached (Add Input > Your Work > this notebook), reuse its translations
# and generated emails instead of redoing hours of GPU work. The longer file wins.
def lines(path):
    with open(path, encoding='utf-8') as f:
        return sum(1 for _ in f)
for name in ('corpus_ar.jsonl', 'generated.jsonl'):
    mine = f'data/processed/{name}'
    for prev in glob.glob(f'/kaggle/input/**/{name}', recursive=True):
        if lines(prev) > (lines(mine) if os.path.exists(mine) else 0):
            shutil.copy(prev, mine)
            print(f'resumed {name} from {prev} ({lines(mine)} rows)')
os.environ.update(ML_THERMAL_GUARD='off', PYTHONUNBUFFERED='1', DOTNET_SYSTEM_GLOBALIZATION_INVARIANT='1')
!pip install -q transformers==4.46.3 onnx==1.17.0 onnxruntime==1.20.1 sentencepiece==0.2.0 sacremoses==0.1.1 accelerate==1.1.1
!nvidia-smi --query-gpu=name,memory.total --format=csv
!wc -l data/processed/*.jsonl"""),

    ("code", """# 2. Translate a balanced sample of the corpus to Arabic with NLLB-200 (~1 h on a T4; skips rows already done)
!python ml/translate.py --train-per-class 3000 --eval-per-class 300 --batch 32
# Save the translations straight away, so a later failure can't cost this hour of GPU time
!zip -qj /kaggle/working/translations.zip data/processed/corpus_ar.jsonl && ls -la /kaggle/working/translations.zip"""),

    ("code", """# 3. Local LLM for paired legitimate/phishing emails (EN + AR): install Ollama, start it, pull Qwen 2.5 7B.
# Optional step: if anything here fails, training still runs on the translations alone.
# (Ollama's installer needs zstd to unpack its release, and Kaggle's image doesn't ship it.)
import shutil, subprocess, time
!apt-get -qq update > /dev/null && apt-get -qq install -y zstd > /dev/null
!curl -fsSL https://ollama.com/install.sh | sh 2>&1 | tail -5
ollama, GENERATE = None, False
if shutil.which('ollama'):
    ollama = subprocess.Popen(['ollama', 'serve'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(10)
    GENERATE = subprocess.run(['ollama', 'pull', 'qwen2.5:7b-instruct'], capture_output=True).returncode == 0
print('pair generation:', 'ON' if GENERATE else 'SKIPPED (Ollama unavailable) - training on translations only')"""),

    ("code", """# 4. Generate pairs - time-boxed so the session always has time left to train
if GENERATE:
    !python ml/generate_pairs.py --pairs-en 300 --pairs-ar 300 --max-minutes 240
if ollama:
    ollama.terminate()   # free the GPU for training"""),

    ("code", """# 5. Normalise everything with the SAME .NET code the API uses, and split (self-contained Linux build)
!./trainer/PhishingAnalyser.Trainer --prepare-transformer data/processed"""),

    ("code", """# 6. Fine-tune the multilingual transformer, export int8 ONNX + parity fixtures (~30-60 min)
!python ml/train_transformer.py --base distilbert/distilbert-base-multilingual-cased --epochs 2 --batch 32"""),

    ("code", """# 7. Package the results for download (Output tab -> results.zip)
!cd /kaggle/working/project && zip -qr /kaggle/working/results.zip models/transformer models/transformer-metrics.json data/processed/corpus_ar.jsonl $(ls data/processed/generated.jsonl 2>/dev/null)
!ls -la /kaggle/working/results.zip
!cat models/transformer-metrics.json | head -60"""),
]

notebook = {
    "nbformat": 4, "nbformat_minor": 5,
    "metadata": {"kernelspec": {"name": "python3", "display_name": "Python 3", "language": "python"},
                 "language_info": {"name": "python"}},
    "cells": [
        {"cell_type": kind, "metadata": {}, "source": text.splitlines(keepends=True),
         **({"outputs": [], "execution_count": None} if kind == "code" else {})}
        for kind, text in cells
    ],
}
out = Path(__file__).with_name("phishing-transformer.ipynb")
out.write_text(json.dumps(notebook, indent=1), encoding="utf-8")
print("wrote", out)
