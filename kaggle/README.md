# Training on Kaggle's free GPU

The laptop's RTX 4050 crashes under sustained compute: "GPU is lost" twice, then a `VIDEO_TDR_FAILURE` blue screen
alongside WHEA hardware errors. The GPU-heavy steps therefore run on Kaggle (free: ~30 GPU-hours/week, 12 h
sessions). The served system doesn't change: the exported ONNX model runs in the .NET API.

## One-time setup
1. Create a free account at **kaggle.com**, then **verify your phone number** (Settings → Phone verification).
   Kaggle requires this before GPUs and internet access can be used.
2. **Upload the bundle:** Datasets → **New Dataset** → drop in `kaggle/phishing-analyser-bundle.zip`
   (78 MB). Name it `phishing-analyser-bundle` and keep it **Private**.
   - The bundle holds the public-corpus training data, the ML scripts, and a self-contained Linux build of the
     .NET trainer (so normalisation matches the API exactly).
   - None of your own email is included.

## Run
1. Code → **New Notebook** → File → **Import Notebook** → `kaggle/phishing-transformer.ipynb`.
2. Right panel:
   - **Accelerator:** GPU T4 x2 (or P100)
   - **Internet:** On
   - **Add Input:** your `phishing-analyser-bundle` dataset
3. **Run All**, or **Save Version → Save & Run All**, which keeps running after you close the browser (recommended).
   It takes about 5–7 hours:
   - translation ~1 h
   - pair generation (capped at 4 h)
   - training ~1 h
4. Download **`results.zip`** from the notebook's **Output** tab and put it in the project root.

## Back on the laptop (CPU only, light)
```bash
unzip results.zip      # -> models/transformer/, data/processed/{corpus_ar,generated}.jsonl
dotnet test            # parity tests: .NET tokens + logits must match Python exactly
```
Then calibration and the end-to-end evaluation run in .NET, and the API picks up `models/transformer/` automatically.

Rebuild the bundle after changing the ML scripts. Use `make_bundle.py`, not PowerShell's `Compress-Archive`:
Windows PowerShell 5.1 writes backslashes into zip entry names, and Kaggle rejects those.
```bash
dotnet publish tools/PhishingAnalyser.Trainer -c Release -r linux-x64 --self-contained true -o kaggle/bundle/trainer
cp ml/*.py ml/requirements.txt kaggle/bundle/ml/ && cp data/processed/corpus.jsonl data/processed/corpus_ar.jsonl kaggle/bundle/data/processed/
python kaggle/make_bundle.py
python kaggle/make_notebook.py
```

## Round 2: realistic Arabic (makes Arabic leave "preview")
The bundle now carries round 1's translations and generated emails, so nothing is redone.
1. **Datasets → phishing-analyser-bundle → New Version**, upload the rebuilt `kaggle/phishing-analyser-bundle.zip`.
2. In the notebook: **File → Import Notebook** → `kaggle/phishing-transformer.ipynb` (replace). Remove the old
   `phishing-translations` input if you like; it's redundant now.
3. **Save Version → Save & Run All** (about 7.5 h). The steps:
   - pull two generator models, one Ollama server per GPU;
   - write an independent Gemma 2 test set;
   - generate Qwen 2.5 14B training pairs;
   - train for 3 epochs and export ONNX.

   `generated.zip` is saved as soon as generation finishes.
4. Download `results.zip` into the project root. Then, locally (CPU):
   ```bash
   unzip -o results.zip
   dotnet run --project tools/PhishingAnalyser.Trainer -c Release -- --prepare-transformer data/processed
   dotnet run --project tools/PhishingAnalyser.Trainer -c Release -- --evaluate-transformer
   ```
   The evaluation promotes Arabic to full support only if realistic Arabic test mail passes all of the following:
   - 100+ legitimate and 100+ phishing test emails;
   - legitimate → "phishing" ≤ 1%;
   - legitimate → any warning ≤ 3%;
   - phishing gets a warning ≥ 80%;
   - translated-mail false positives ≤ 1%.

   Otherwise it stays in preview, and the report says which check failed.
