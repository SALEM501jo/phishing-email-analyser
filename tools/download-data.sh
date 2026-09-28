#!/usr/bin/env bash
# Downloads every training corpus into data/raw/ (git-ignored). ~1 GB unpacked. Needs curl, git, python3 (+py7zr).
#   Zenodo "Phishing Email Curated Datasets" (Champa et al., CC BY 4.0) - old phishing / spam / ham, 1990s-2008
#   phishing_pot (rf-peixoto)                                         - real phishing captured 2022-2026
#   untroubled.org spam archive (Bruce Guenter)                       - real spam 2024-2025
#   Public mailing-list archives (Python, Fedora, Mailman)           - real legitimate mail 2024-2026
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p data/raw/modern_ham data/raw/modern_spam
cd data/raw

for f in Nazario.csv Nazario_5.csv SpamAssasin.csv CEAS_08.csv TREC_05.csv TREC_06.csv TREC_07.csv Nigerian_Fraud.csv; do
  [ -f "$f" ] || curl -fSL -o "$f" "https://zenodo.org/records/8339691/files/$f?download=1"
done

[ -d phishing_pot ] || git clone --depth 1 https://github.com/rf-peixoto/phishing_pot.git

for y in 2024 2025; do
  [ -d "modern_spam/$y" ] || { curl -fSL -o "modern_spam/$y.7z" "http://untroubled.org/spam/$y.7z"
                              python3 -c "import py7zr,sys; py7zr.SevenZipFile(sys.argv[1]).extractall(sys.argv[2])" "modern_spam/$y.7z" modern_spam; }
done

lists=(
  "mail.python.org python-list@python.org"
  "mail.python.org python-announce-list@python.org"
  "mail.python.org python-ideas@python.org"
  "lists.fedoraproject.org users@lists.fedoraproject.org"
  "lists.fedoraproject.org devel@lists.fedoraproject.org"
  "lists.fedoraproject.org announce@lists.fedoraproject.org"
  "lists.mailman3.org mailman-users@mailman3.org"
)
for entry in "${lists[@]}"; do
  set -- $entry
  for y in 2024 2025 2026; do
    out="modern_ham/$2-$y.mbox.gz"
    [ -s "$out" ] || curl -fsSL -o "$out" "https://$1/archives/list/$2/export/$2-$y.mbox.gz?start=$y-01-01&end=$y-12-31" || rm -f "$out"
  done
done

echo "Done. Train with: dotnet run --project tools/PhishingAnalyser.Trainer -c Release"
