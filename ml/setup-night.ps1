# One-shot, unattended setup of the offline ML tooling (~10 GB of downloads). Run it before bed:
#
#   powershell -ExecutionPolicy Bypass -File "G:\Downloads\phishing emails project\ml\setup-night.ps1"
#
# Everything is stored on G: (C: has little free space):
#   G:\ml-cache\venv         Python virtual environment (PyTorch + CUDA, transformers, ONNX tooling)
#   G:\ml-cache\pip          pip download cache
#   G:\ml-cache\huggingface  base transformer + NLLB-200 translation model
#   G:\ml-cache\ollama       local LLM used to generate paired training emails
# Progress is logged to ml\setup-night.log. Safe to re-run: finished steps are skipped.

$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot
$cache = "G:\ml-cache"
$venv = "$cache\venv"
$python = "$venv\Scripts\python.exe"

New-Item -ItemType Directory -Force "$cache\pip", "$cache\huggingface", "$cache\ollama", "$cache\tmp" | Out-Null
Start-Transcript -Path "$PSScriptRoot\setup-night.log" -Append

function Step($name) { Write-Host "`n==== $(Get-Date -Format HH:mm:ss)  $name ====" -ForegroundColor Cyan }

# Keep every large download and temp file off C:
$env:PIP_CACHE_DIR = "$cache\pip"
$env:HF_HOME = "$cache\huggingface"
$env:TMP = "$cache\tmp"; $env:TEMP = "$cache\tmp"
$env:OLLAMA_MODELS = "$cache\ollama"
# Persist the two model-location variables for your user so the Ollama app and later scripts use G: too.
[Environment]::SetEnvironmentVariable("OLLAMA_MODELS", "$cache\ollama", "User")
[Environment]::SetEnvironmentVariable("HF_HOME", "$cache\huggingface", "User")

try {
    Step "1/7 Python virtual environment"
    if (-not (Test-Path $python)) { python -m venv $venv }
    & $python -m pip install --upgrade pip --quiet

    Step "2/7 PyTorch with CUDA 12.4 (~2.5 GB)"
    & $python -c "import torch" 2>$null
    if ($LASTEXITCODE -ne 0) { & $python -m pip install torch --index-url https://download.pytorch.org/whl/cu124 }
    & $python -c "import torch; print('torch', torch.__version__, '| CUDA available:', torch.cuda.is_available(), '|', torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'NO GPU')"

    Step "3/7 transformers / ONNX / data tooling"
    & $python -m pip install -r "$PSScriptRoot\requirements.txt"

    Step "4/7 Hugging Face models (base transformers + NLLB-200 translation, ~3.5 GB)"
    & $python -c @"
from huggingface_hub import snapshot_download
for repo in ['distilbert/distilbert-base-multilingual-cased',   # WordPiece tokenizer - natively supported by Microsoft.ML.Tokenizers
             'intfloat/multilingual-e5-small',                   # stronger multilingual encoder (XLM-R tokenizer) - evaluated as an alternative
             'facebook/nllb-200-distilled-600M']:                # English -> Arabic translation for translate-train
    print('downloading', repo, flush=True)
    print(' ->', snapshot_download(repo, allow_patterns=['*.json', '*.txt', '*.model', '*.safetensors', 'sentencepiece*']), flush=True)
"@

    Step "5/7 Local LLM for paired email generation: qwen2.5:7b-instruct (~4.7 GB)"
    Get-Process ollama* -ErrorAction SilentlyContinue | Stop-Process -Force   # restart so it picks up OLLAMA_MODELS
    Start-Process -WindowStyle Hidden -FilePath "ollama" -ArgumentList "serve"
    Start-Sleep -Seconds 5
    ollama pull qwen2.5:7b-instruct
    ollama list

    Step "Tooling installed - starting the overnight data jobs"

    # Both jobs are resumable: if the night is cut short, re-running continues where they stopped.
    Step "6/7 Translate part of the corpus to Arabic with NLLB-200 (GPU, ~30-60 min)"
    if (Test-Path "$project\data\processed\corpus.jsonl") {
        & $python "$PSScriptRoot\translate.py" --train-per-class 3000 --eval-per-class 300
    } else {
        Write-Host "corpus.jsonl missing - run the .NET export first (see ml/README.md). Skipping." -ForegroundColor Yellow
    }

    Step "7/7 Generate paired legitimate/phishing emails, English + Arabic (GPU, a few hours)"
    & $python "$PSScriptRoot\generate_pairs.py" --pairs-en 500 --pairs-ar 400

    Step "DONE"
    Write-Host "Setup + overnight data jobs finished. Tell Claude 'setup finished' to continue with training." -ForegroundColor Green
}
catch {
    Write-Host "FAILED: $_" -ForegroundColor Red
    Write-Host "Re-run the script to resume; completed steps are skipped." -ForegroundColor Yellow
}
finally {
    Stop-Transcript
}
