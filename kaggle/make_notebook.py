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
import glob, os, shutil, subprocess
src = os.path.dirname(os.path.dirname(glob.glob('/kaggle/input/**/trainer/PhishingAnalyser.Trainer', recursive=True)[0]))
PROJECT = '/kaggle/working/project'
if not os.path.exists(PROJECT):
    shutil.copytree(src, PROJECT)
os.chmod(f'{PROJECT}/trainer/PhishingAnalyser.Trainer', 0o755)
os.chdir(PROJECT)
os.environ.update(ML_THERMAL_GUARD='off', PYTHONUNBUFFERED='1', DOTNET_SYSTEM_GLOBALIZATION_INVARIANT='1')
!pip install -q transformers==4.46.3 "optimum[onnxruntime]==1.23.3" onnx==1.17.0 onnxruntime==1.20.1 sentencepiece==0.2.0 sacremoses==0.1.1 accelerate==1.1.1
!nvidia-smi --query-gpu=name,memory.total --format=csv
!wc -l data/processed/*.jsonl"""),

    ("code", """# 2. Translate a balanced sample of the corpus to Arabic with NLLB-200 (~30-60 min on a T4)
!python ml/translate.py --train-per-class 3000 --eval-per-class 300 --batch 32"""),

    ("code", """# 3. Local LLM for paired legitimate/phishing emails (EN + AR): install Ollama, start it, pull Qwen 2.5 7B
!curl -fsSL https://ollama.com/install.sh | sh > /dev/null
import subprocess, time
ollama = subprocess.Popen(['ollama', 'serve'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(10)
!ollama pull qwen2.5:7b-instruct 2>&1 | tail -1"""),

    ("code", """# 4. Generate pairs - time-boxed so the session always has time left to train
!python ml/generate_pairs.py --pairs-en 300 --pairs-ar 300 --max-minutes 240
ollama.terminate()   # free the GPU for training"""),

    ("code", """# 5. Normalise everything with the SAME .NET code the API uses, and split (self-contained Linux build)
!./trainer/PhishingAnalyser.Trainer --prepare-transformer data/processed"""),

    ("code", """# 6. Fine-tune the multilingual transformer, export int8 ONNX + parity fixtures (~30-60 min)
!python ml/train_transformer.py --base distilbert/distilbert-base-multilingual-cased --epochs 2 --batch 32"""),

    ("code", """# 7. Package the results for download (Output tab -> results.zip)
!cd /kaggle/working/project && zip -qr /kaggle/working/results.zip models/transformer models/transformer-metrics.json data/processed/corpus_ar.jsonl data/processed/generated.jsonl
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
