# Offline ML pipeline: multilingual transformer (English + Arabic)

Python is used **only here, offline**, to fine-tune a transformer on the local GPU. The production API runs the
exported model with ONNX Runtime inside ASP.NET Core, so the served system stays pure .NET. The linear ML.NET model
stays as the explainer that supplies the "strongest cues" words, and as the fallback.

**All text normalisation happens in .NET** (`EmailTextNormalizer`). Python only ever sees text the .NET code has
already normalised, so training and inference can't disagree about preprocessing.

| # | Step | Where | Output |
|---|---|---|---|
| 0 | One-time tooling setup (+ steps 2 and 3 overnight) | `ml/setup-night.ps1` | `G:\ml-cache\…` |
| 1 | Export the cleaned corpus with confident-learning flags | `dotnet run --project tools/PhishingAnalyser.Trainer -c Release -- --export-corpus` | `data/processed/corpus.jsonl` |
| 2 | Translate part of it to Arabic (NLLB-200) | `python ml/translate.py` | `corpus_ar.jsonl` |
| 3 | Generate paired legitimate/phishing emails (local LLM) | `python ml/generate_pairs.py` | `generated.jsonl` |
| 4 | Normalise everything, split | `dotnet run … -- --prepare-transformer` | `transformer_{train,val,test}.jsonl` |
| 5 | Fine-tune + export ONNX (int8) + parity fixtures | `python ml/train_transformer.py` | `models/transformer/` |
| 6 | Parity tests: .NET tokens and logits must match Python | `dotnet test` | — |
| 7 | Calibrate, tune thresholds, end-to-end evaluation | `dotnet run … -- --evaluate-transformer` | `models/transformer/model-info.json` |

`python` means `G:\ml-cache\venv\Scripts\python.exe`.

## Why each piece exists
- **Paired generation.** No public corpus has modern receipts, OTP codes, shipping notices or newsletters, and none has
  Arabic mail at all. For each (brand, email type, language) the local LLM writes a genuine email *and* a phishing twin.
  Both classes share the generator's style, so "sounds AI-written" can't become a shortcut for either.
- **Translate-train.** Real Arabic phishing corpora are scarce, and machine translation is the standard way to
  bootstrap a new language. Translated test data measures cross-lingual transfer, not real-world accuracy, and is
  reported separately.
- **Parity fixtures.** A tokenizer mismatch between Python and .NET would silently feed the model garbage.
  `parity.json` pins the exact token ids and logits.
- **Splits.** Translated rows keep their source email's split, and generated pairs are split by pair, so no test
  email is a translation or twin of a training email.
