# One-shot, unattended setup of the offline ML tooling (~10 GB of downloads), followed by the long data jobs:
#
#   powershell -ExecutionPolicy Bypass -File "G:\Downloads\phishing emails project\ml\setup-night.ps1"
#
# Everything is stored on G: (C: has little free space):
#   G:\ml-cache\venv         Python virtual environment (PyTorch + CUDA, transformers, ONNX tooling)
#   G:\ml-cache\pip          pip download cache
#   G:\ml-cache\huggingface  base transformer + NLLB-200 translation model
#   G:\ml-cache\ollama       local LLM used to generate paired training emails
# Progress: ml\setup-progress.txt (plain UTF-8). Safe to re-run: finished steps are skipped, jobs resume.

# Windows PowerShell 5.1 treats ANY stderr output of a native program as an error under "Stop" (e.g. pip warnings
# or a deliberately failing "import torch" probe), so success is judged by exit codes instead.
$ErrorActionPreference = "Continue"
$project = Split-Path -Parent $PSScriptRoot
$cache = "G:\ml-cache"
$venv = "$cache\venv"
$python = "$venv\Scripts\python.exe"
$progress = "$PSScriptRoot\setup-progress.txt"

New-Item -ItemType Directory -Force "$cache\pip", "$cache\huggingface", "$cache\ollama", "$cache\tmp" | Out-Null

function Log([string]$line, [string]$color = "Gray") {
    Write-Host $line -ForegroundColor $color
    # Add-Content opens the file exclusively; if anything is reading it at that instant (an editor, a watcher,
    # antivirus), retry briefly and otherwise drop the log line - logging must never disturb the actual work.
    for ($attempt = 0; $attempt -lt 5; $attempt++) {
        try { [System.IO.File]::AppendAllText($progress, $line + [Environment]::NewLine); return }
        catch [System.IO.IOException] { Start-Sleep -Milliseconds 50 }
    }
}

function Step([string]$name) { Log "`n==== $(Get-Date -Format HH:mm:ss)  $name ====" "Cyan" }

# Runs a native command, mirrors its output (stdout + stderr) to the console and the progress file,
# and fails the step on a non-zero exit code.
function Run([string]$what, [scriptblock]$command) {
    & $command 2>&1 | ForEach-Object { Log "$_" }
    if ($LASTEXITCODE -ne 0) { throw "$what failed (exit code $LASTEXITCODE)" }
}

function Probe([scriptblock]$command) {
    & $command *> $null
    return $LASTEXITCODE -eq 0
}

# Keep every large download and temp file off C:
$env:PIP_CACHE_DIR = "$cache\pip"
$env:HF_HOME = "$cache\huggingface"
$env:TMP = "$cache\tmp"; $env:TEMP = "$cache\tmp"
$env:OLLAMA_MODELS = "$cache\ollama"
$env:PYTHONUNBUFFERED = "1"
$env:PYTHONIOENCODING = "utf-8"
# Persist the two model-location variables for your user so the Ollama app and later scripts use G: too.
[Environment]::SetEnvironmentVariable("OLLAMA_MODELS", "$cache\ollama", "User")
[Environment]::SetEnvironmentVariable("HF_HOME", "$cache\huggingface", "User")

Log "`n######## setup started $(Get-Date -Format 'yyyy-MM-dd HH:mm') ########" "White"
try {
    Step "1/7 Python virtual environment"
    # A folder without a working pip is a half-created environment (e.g. an interrupted earlier run): recreate it.
    if (-not (Test-Path $python) -or -not (Probe { & $python -m pip --version })) {
        Log "creating a fresh environment in $venv"
        Run "venv" { python -m venv --clear $venv }
    }
    Run "pip upgrade" { & $python -m pip install --upgrade pip --quiet --disable-pip-version-check }

    Step "2/7 PyTorch with CUDA 12.4 (~2.5 GB)"
    if (-not (Probe { & $python -c "import torch" })) {
        Run "PyTorch install" { & $python -m pip install torch --index-url https://download.pytorch.org/whl/cu124 --disable-pip-version-check }
    }
    Run "GPU check" { & $python -c "import torch; ok=torch.cuda.is_available(); print('torch', torch.__version__, '| CUDA available:', ok, '|', torch.cuda.get_device_name(0) if ok else 'NO GPU'); raise SystemExit(0 if ok else 3)" }

    Step "3/7 transformers / ONNX / data tooling"
    Run "requirements" { & $python -m pip install -r "$PSScriptRoot\requirements.txt" --disable-pip-version-check }

    Step "4/7 Hugging Face models (base transformers + NLLB-200 translation, ~3.5 GB)"
    # Plain folders (local_dir) instead of the Hugging Face cache: the cache uses symlinks, which Windows only
    # allows with admin rights or Developer Mode ("WinError 1314 A required privilege is not held").
    Run "model downloads" { & $python -c @"
from huggingface_hub import snapshot_download
models = {
    'distilbert-base-multilingual-cased': 'distilbert/distilbert-base-multilingual-cased',  # WordPiece - natively supported by Microsoft.ML.Tokenizers
    'multilingual-e5-small': 'intfloat/multilingual-e5-small',                              # stronger multilingual encoder, evaluated as an alternative
    'nllb-200-distilled-600M': 'facebook/nllb-200-distilled-600M',                          # English -> Arabic translation for translate-train
}
for folder, repo in models.items():
    print('downloading', repo, flush=True)
    path = snapshot_download(repo, local_dir=r'$cache' + '/models/' + folder,
                             # NLLB publishes only pytorch_model.bin (no safetensors), so allow both weight formats.
                             allow_patterns=['*.json', '*.txt', '*.model', '*.safetensors', '*.bin', 'sentencepiece*'])
    print(' ->', path, flush=True)
"@ }

    Step "5/7 Local LLM for paired email generation: qwen2.5:7b-instruct (~4.7 GB)"
    Get-Process ollama* -ErrorAction SilentlyContinue | Stop-Process -Force   # restart so it picks up OLLAMA_MODELS
    Start-Process -WindowStyle Hidden -FilePath "ollama" -ArgumentList "serve"
    Start-Sleep -Seconds 8
    Run "ollama pull" { ollama pull qwen2.5:7b-instruct }
    Run "ollama list" { ollama list }

    Step "Tooling installed - starting the long data jobs"

    # Both jobs are resumable: if interrupted, re-running continues where they stopped.
    Step "6/7 Translate part of the corpus to Arabic with NLLB-200 (GPU, ~30-60 min)"
    if (Test-Path "$project\data\processed\corpus.jsonl") {
        Run "translation" { & $python "$PSScriptRoot\translate.py" --train-per-class 3000 --eval-per-class 300 }
    } else {
        Log "corpus.jsonl missing - run the .NET export first (see ml/README.md). Skipping." "Yellow"
    }

    Step "7/7 Generate paired legitimate/phishing emails, English + Arabic (GPU, a few hours)"
    Run "generation" { & $python "$PSScriptRoot\generate_pairs.py" --pairs-en 500 --pairs-ar 400 }

    Step "DONE"
    Log "Setup + data jobs finished. Tell Claude 'setup finished' to continue with training." "Green"
}
catch {
    Log "FAILED: $_" "Red"
    Log "Re-run the script to resume; completed steps are skipped." "Yellow"
}
