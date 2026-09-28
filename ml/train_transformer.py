"""
Fine-tunes a multilingual transformer (English + Arabic) as the 3-class email classifier and exports it to ONNX
for the .NET API. Python is used ONLY here, offline; production inference is ONNX Runtime inside ASP.NET Core.

Inputs  data/processed/transformer_{train,val,test}.jsonl  - already normalised by the .NET trainer
Outputs models/transformer/
          model.onnx               int8 dynamically-quantised graph (CPU-friendly for the VPS)
          vocab.txt / sentencepiece.bpe.model + tokenizer_config.json
          transformer-info.json    classes, max length, tokenizer type, base model
          parity.json              token ids + logits for sample texts - the .NET tests check they match exactly
        models/transformer-metrics.json  per-language / per-source evaluation

    G:\\ml-cache\\venv\\Scripts\\python ml\\train_transformer.py --base distilbert/distilbert-base-multilingual-cased
"""
import argparse
import json
import math
import random
import shutil
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import f1_score, precision_recall_fscore_support, roc_auc_score
from torch.utils.data import DataLoader, Dataset
from transformers import AutoModelForSequenceClassification, AutoTokenizer, get_linear_schedule_with_warmup

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "processed"
OUT = ROOT / "models" / "transformer"
CLASSES = ["legitimate", "phishing", "spam"]  # alphabetical = same key order as the ML.NET model


def load(split):
    return [json.loads(l) for l in (DATA / f"transformer_{split}.jsonl").read_text(encoding="utf-8").splitlines()]


class Emails(Dataset):
    def __init__(self, rows):
        self.rows = rows
    def __len__(self):
        return len(self.rows)
    def __getitem__(self, i):
        return self.rows[i]


def collate(tokenizer, max_len):
    def fn(batch):
        enc = tokenizer([r["text"] for r in batch], truncation=True, max_length=max_len, padding=True, return_tensors="pt")
        enc["labels"] = torch.tensor([CLASSES.index(r["label"]) for r in batch])
        return enc
    return fn


def balance(rows, rng, max_old_per_class, arabic_boost):
    """Cap the huge old-English pools and repeat Arabic rows so the rarer language isn't drowned out."""
    by_key = defaultdict(list)
    for r in rows:
        by_key[(r["language"], r["modern"], r["label"])].append(r)
    out = []
    for (lang, modern, label), group in by_key.items():
        rng.shuffle(group)
        if lang == "en" and not modern:
            group = group[:max_old_per_class]
        out += group * (arabic_boost if lang == "ar" else 1)
    rng.shuffle(out)
    return out


@torch.no_grad()
def predict(model, loader, device):
    model.eval()
    probs = []
    for batch in loader:
        batch = {k: v.to(device) for k, v in batch.items() if k != "labels"}
        with torch.autocast(device_type="cuda", dtype=torch.float16, enabled=device == "cuda"):
            logits = model(**batch).logits
        probs.append(torch.softmax(logits.float(), dim=-1).cpu().numpy())
    return np.concatenate(probs)


def report(rows, probs):
    """Phishing-vs-rest metrics overall and by language / source."""
    def metrics(idx):
        y = np.array([rows[i]["label"] == "phishing" for i in idx])
        p = probs[idx, CLASSES.index("phishing")]
        pred = probs[idx].argmax(1) == CLASSES.index("phishing")
        prec, rec, f1, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
        auc = roc_auc_score(y, p) if 0 < y.sum() < len(y) else float("nan")
        acc = float(np.mean(probs[idx].argmax(1) == np.array([CLASSES.index(rows[i]["label"]) for i in idx])))
        return {"n": len(idx), "phishing": int(y.sum()), "precision": round(prec, 4), "recall": round(rec, 4),
                "f1": round(f1, 4), "auc": round(auc, 4), "threeClassAccuracy": round(acc, 4)}
    groups = defaultdict(list)
    for i, r in enumerate(rows):
        groups["all"].append(i)
        groups[f"lang:{r['language']}"].append(i)
        kind = "generated" if r["source"].startswith("generated") else "translated" if "(translated)" in r["source"] else ("modern" if r["modern"] else "old")
        groups[f"{r['language']}:{kind}"].append(i)
    return {k: metrics(np.array(v)) for k, v in sorted(groups.items()) if len(v) >= 20}


def main():
    ap = argparse.ArgumentParser()
    # Local copy downloaded by setup-night.ps1 (distilbert/distilbert-base-multilingual-cased); a hub id also works.
    local_base = Path(r"G:\ml-cache\models\distilbert-base-multilingual-cased")
    ap.add_argument("--base", default=str(local_base) if local_base.exists() else "distilbert/distilbert-base-multilingual-cased")
    ap.add_argument("--max-len", type=int, default=256)
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--lr", type=float, default=3e-5)
    ap.add_argument("--max-old-per-class", type=int, default=8000)
    ap.add_argument("--arabic-boost", type=int, default=2)
    args = ap.parse_args()

    rng = random.Random(42)
    torch.manual_seed(42)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    train, val, test = balance(load("train"), rng, args.max_old_per_class, args.arabic_boost), load("val"), load("test")
    print(f"train={len(train)} val={len(val)} test={len(test)} device={device}")
    print("train mix:", Counter((r["language"], r["label"]) for r in train))

    tokenizer = AutoTokenizer.from_pretrained(args.base)
    model = AutoModelForSequenceClassification.from_pretrained(args.base, num_labels=len(CLASSES),
        id2label=dict(enumerate(CLASSES)), label2id={c: i for i, c in enumerate(CLASSES)}).to(device)

    # Class weights (sqrt inverse frequency) - phishing is the minority class but the one that matters.
    counts = Counter(r["label"] for r in train)
    weights = torch.tensor([math.sqrt(len(train) / (len(CLASSES) * counts[c])) for c in CLASSES], dtype=torch.float, device=device)
    loss_fn = torch.nn.CrossEntropyLoss(weight=weights)

    coll = collate(tokenizer, args.max_len)
    train_loader = DataLoader(Emails(train), batch_size=args.batch, shuffle=True, collate_fn=coll)
    val_loader = DataLoader(Emails(val), batch_size=64, collate_fn=coll)
    test_loader = DataLoader(Emails(test), batch_size=64, collate_fn=coll)

    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
    steps = len(train_loader) * args.epochs
    scheduler = get_linear_schedule_with_warmup(optimizer, int(0.06 * steps), steps)
    scaler = torch.amp.GradScaler(enabled=device == "cuda")

    best_f1, best_dir = -1.0, OUT.parent / "transformer-best"
    started = time.time()
    for epoch in range(args.epochs):
        model.train()
        for step, batch in enumerate(train_loader):
            batch = {k: v.to(device) for k, v in batch.items()}
            labels = batch.pop("labels")
            with torch.autocast(device_type="cuda", dtype=torch.float16, enabled=device == "cuda"):
                loss = loss_fn(model(**batch).logits.float(), labels)
            optimizer.zero_grad()
            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            scaler.step(optimizer)
            scaler.update()
            scheduler.step()
            if step % 200 == 0:
                print(f"epoch {epoch + 1} step {step}/{len(train_loader)} loss {loss.item():.4f} ({(time.time() - started) / 60:.1f} min)", flush=True)

        val_probs = predict(model, val_loader, device)
        y = [r["label"] == "phishing" for r in val]
        f1 = f1_score(y, val_probs.argmax(1) == CLASSES.index("phishing"))
        print(f"epoch {epoch + 1}: validation phishing F1 = {f1:.4f}", flush=True)
        if f1 > best_f1:
            best_f1 = f1
            shutil.rmtree(best_dir, ignore_errors=True)
            model.save_pretrained(best_dir)
            tokenizer.save_pretrained(best_dir)

    # Evaluate the best checkpoint on the untouched test split.
    model = AutoModelForSequenceClassification.from_pretrained(best_dir).to(device)
    metrics = {"base": args.base, "maxLength": args.max_len, "epochs": args.epochs, "bestValF1": round(best_f1, 4),
               "trainMinutes": round((time.time() - started) / 60, 1), "test": report(test, predict(model, test_loader, device))}
    (OUT.parent / "transformer-metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics["test"], indent=2))

    export_onnx(best_dir, tokenizer, args, test)


def export_onnx(best_dir, tokenizer, args, test):
    """ONNX export + int8 dynamic quantisation, plus parity fixtures for the .NET tests."""
    from onnxruntime.quantization import QuantType, quantize_dynamic
    from optimum.onnxruntime import ORTModelForSequenceClassification
    import onnxruntime as ort

    shutil.rmtree(OUT, ignore_errors=True)
    tmp = OUT.parent / "transformer-fp32"
    ORTModelForSequenceClassification.from_pretrained(best_dir, export=True).save_pretrained(tmp)
    OUT.mkdir(parents=True, exist_ok=True)
    quantize_dynamic(str(tmp / "model.onnx"), str(OUT / "model.onnx"), weight_type=QuantType.QInt8)
    tokenizer.save_pretrained(OUT)
    shutil.rmtree(tmp, ignore_errors=True)

    tok_type = "wordpiece" if (OUT / "vocab.txt").exists() else "sentencepiece"
    info = {"base": args.base, "classes": CLASSES, "maxLength": args.max_len, "tokenizer": tok_type,
            "lowercase": bool(getattr(tokenizer, "do_lower_case", False))}
    (OUT / "transformer-info.json").write_text(json.dumps(info, indent=2), encoding="utf-8")

    # Parity fixtures: the exact ids and the quantised model's logits for a few real test texts (both languages).
    session = ort.InferenceSession(str(OUT / "model.onnx"))
    input_names = {i.name for i in session.get_inputs()}
    samples = [r["text"] for r in test if r["language"] == "en"][:6] + [r["text"] for r in test if r["language"] == "ar"][:6]
    fixtures = []
    for text in samples:
        enc = tokenizer(text, truncation=True, max_length=args.max_len, return_tensors="np")
        feed = {k: v.astype(np.int64) for k, v in enc.items() if k in input_names}
        logits = session.run(None, feed)[0][0]
        fixtures.append({"text": text, "inputIds": enc["input_ids"][0].tolist(), "logits": [float(x) for x in logits]})
    (OUT / "parity.json").write_text(json.dumps(fixtures, ensure_ascii=False, indent=1), encoding="utf-8")
    size = (OUT / "model.onnx").stat().st_size / 1e6
    print(f"Exported {OUT / 'model.onnx'} ({size:.0f} MB, {tok_type} tokenizer)")


if __name__ == "__main__":
    main()
