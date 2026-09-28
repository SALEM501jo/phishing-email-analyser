"""
Translate-train augmentation: machine-translates part of the cleaned English corpus into Arabic with Meta's
open NLLB-200 (distilled 600M) on the local GPU, so the multilingual transformer sees Arabic phishing, spam and
legitimate mail. Real Arabic samples are scarce; translation is the standard way to bootstrap a new language.

Reads  data/processed/corpus.jsonl      (written by the .NET trainer with --export-corpus)
Writes data/processed/corpus_ar.jsonl   (same rows, Arabic text, language "ar", keeps the original split)

Translated rows keep their original split, so a translated test email is never a translation of a training email.
Translated test data is reported separately from real Arabic data - it measures transfer, not real-world accuracy.

    G:\\ml-cache\\venv\\Scripts\\python ml\\translate.py --train-per-class 3000 --eval-per-class 300
"""
import argparse
import json
import random
import re
import time

import watchdog
from pathlib import Path

import torch
from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "data" / "processed" / "corpus.jsonl"
OUT = ROOT / "data" / "processed" / "corpus_ar.jsonl"
MODEL = r"G:\ml-cache\models\nllb-200-distilled-600M"  # facebook/nllb-200-distilled-600M, downloaded by setup-night.ps1

URL_OR_EMAIL = re.compile(r"(https?://\S+|www\.\S+|[\w.+-]+@[\w-]+(?:\.[\w-]+)+)")


def mask(text):
    """Replace URLs/addresses with numbered placeholders NLLB leaves alone, so links survive translation."""
    found = []
    def sub(m):
        found.append(m.group(0))
        return f" X{len(found) - 1}X "
    return URL_OR_EMAIL.sub(sub, text), found


def unmask(text, found):
    for i, value in enumerate(found):
        if f"X{i}X" in text:
            text = text.replace(f"X{i}X", value)
        else:
            text += f" {value}"   # placeholder lost - keep the link at the end rather than dropping it
    return text


def chunks(text, limit=350):
    """Sentence-ish chunks short enough for the translator's context."""
    parts, current = [], ""
    for piece in re.split(r"(?<=[.!?\n])\s+", text):
        if len(current) + len(piece) > limit and current:
            parts.append(current)
            current = ""
        current += (" " if current else "") + piece
    if current:
        parts.append(current)
    return [p[:600] for p in parts if p.strip()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-per-class", type=int, default=3000)
    ap.add_argument("--eval-per-class", type=int, default=300)
    ap.add_argument("--max-body", type=int, default=1200)
    ap.add_argument("--batch", type=int, default=24)
    args = ap.parse_args()

    rows = [json.loads(line) for line in SRC.read_text(encoding="utf-8").splitlines()]
    rng = random.Random(11)
    groups = []
    for split, per_class in (("train", args.train_per_class), ("tune", args.eval_per_class), ("test", args.eval_per_class)):
        for cls in ("legitimate", "spam", "phishing"):
            pool = [r for r in rows if r["split"] == split and r["class"] == cls and not r.get("labelIssue")]
            # Prefer modern mail: that's the distribution we care about.
            pool.sort(key=lambda r: (not r["modern"], rng.random()))
            groups.append(pool[:per_class])

    # Interleave all (split, class) groups proportionally, so a run that is cut short still leaves a balanced,
    # usable sample (an earlier ordered run stopped after 2,224 rows that were ALL legitimate training mail).
    selected = [row for _, row in sorted(
        ((i / len(group), row) for group in groups for i, row in enumerate(group)), key=lambda x: x[0])]

    done = set()
    if OUT.exists():
        done = {json.loads(l)["id"] for l in OUT.read_text(encoding="utf-8").splitlines()}
    todo = [r for r in selected if r["id"] + "-ar" not in done]
    print(f"{len(selected)} selected, {len(todo)} still to translate")

    device = "cuda" if torch.cuda.is_available() else "cpu"
    tokenizer = AutoTokenizer.from_pretrained(MODEL, src_lang="eng_Latn")
    model = AutoModelForSeq2SeqLM.from_pretrained(MODEL, torch_dtype=torch.float16 if device == "cuda" else torch.float32).to(device).eval()
    target = tokenizer.convert_tokens_to_ids("arb_Arab")

    def translate(texts):
        batch = tokenizer(texts, return_tensors="pt", padding=True, truncation=True, max_length=256).to(device)
        with torch.no_grad():
            out = model.generate(**batch, forced_bos_token_id=target, max_new_tokens=320, num_beams=1)
        return tokenizer.batch_decode(out, skip_special_tokens=True)

    started = time.time()
    watchdog.start(limit_seconds=600)   # a lost laptop GPU hangs CUDA forever - fail loudly instead
    with OUT.open("a", encoding="utf-8") as out:
        for start in range(0, len(todo), 8):
            group = todo[start:start + 8]
            # Flatten subjects + body chunks of 8 emails into one batched translation job.
            jobs, layout = [], []
            for row in group:
                subject, subject_links = mask(row["subject"] or "")
                body, body_links = mask((row["body"] or "")[:args.max_body])
                pieces = chunks(body)
                layout.append((row, subject_links, body_links, len(pieces)))
                jobs += [subject or "."] + pieces
            results = []
            for i in range(0, len(jobs), args.batch):
                results += translate(jobs[i:i + args.batch])

            cursor = 0
            for row, subject_links, body_links, n in layout:
                subject_ar = unmask(results[cursor], subject_links)
                body_ar = unmask(" ".join(results[cursor + 1: cursor + 1 + n]), body_links)
                cursor += 1 + n
                out.write(json.dumps({**row, "id": row["id"] + "-ar", "subject": subject_ar, "body": body_ar,
                                      "language": "ar", "source": row["source"] + " (translated)"}, ensure_ascii=False) + "\n")
            out.flush()
            watchdog.beat()
            watchdog.cool_down()   # this laptop's GPU overheats under sustained load
            if (start // 8) % 25 == 0:
                done_n = start + len(group)
                print(f"{done_n}/{len(todo)} translated ({done_n / (time.time() - started) * 60:.0f}/min)", flush=True)

    print(f"Done in {(time.time() - started) / 60:.1f} min -> {OUT}")


if __name__ == "__main__":
    main()
