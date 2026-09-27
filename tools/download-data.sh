#!/usr/bin/env bash
# Downloads the training corpora (Champa et al., "Phishing Email Curated Datasets", Zenodo, CC BY 4.0).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p data/raw
for f in Nazario.csv Nazario_5.csv SpamAssasin.csv; do
  [ -f "data/raw/$f" ] || curl -fSL -o "data/raw/$f" "https://zenodo.org/records/8339691/files/$f?download=1"
done
echo "Done. Train with: dotnet run --project tools/PhishingAnalyser.Trainer -c Release"
