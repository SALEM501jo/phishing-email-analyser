"""
Generates PAIRED training emails with a local open-source LLM (Ollama, default qwen2.5:7b-instruct).

Why pairs: public data has no modern legitimate transactional/marketing mail (receipts, OTPs, shipping notices,
newsletters) - and no Arabic mail at all. For each (brand, email type, language) we generate BOTH a genuine email
and a phishing email from the same generator with the same scenario. Because both classes share the generator's
writing style, "sounds AI-written" cannot become a shortcut for either class; the model has to learn the real
differences (credential requests, pressure, payment redirection, look-alike links).

Output: data/processed/generated.jsonl in the ExchangeRow format the .NET trainer reads. Resumable: re-running
skips pairs that already exist. Used for training (85%) and a held-out generated test split (15%, split by pair).

    G:\\ml-cache\\venv\\Scripts\\python ml\\generate_pairs.py --pairs-en 500 --pairs-ar 400
"""
import argparse
import hashlib
import json
import random
import re
import sys
import time

import watchdog
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "processed" / "generated.jsonl"
OLLAMA = "http://localhost:11434/api/chat"

# (display name, genuine domain, markets)  - markets: "global" for everyone, "mena" for Arabic-first brands
BRANDS = [
    ("PayPal", "paypal.com", "global"), ("Microsoft 365", "microsoft.com", "global"), ("Apple", "apple.com", "global"),
    ("Google", "google.com", "global"), ("Amazon", "amazon.com", "global"), ("Netflix", "netflix.com", "global"),
    ("DHL Express", "dhl.com", "global"), ("FedEx", "fedex.com", "global"), ("LinkedIn", "linkedin.com", "global"),
    ("DocuSign", "docusign.net", "global"), ("Dropbox", "dropbox.com", "global"), ("Spotify", "spotify.com", "global"),
    ("Coinbase", "coinbase.com", "global"), ("Booking.com", "booking.com", "global"), ("Uber", "uber.com", "global"),
    ("Aramex", "aramex.com", "mena"), ("Arab Bank", "arabbank.jo", "mena"), ("Housing Bank", "hbtf.com", "mena"),
    ("Zain Jordan", "jo.zain.com", "mena"), ("Orange Jordan", "orange.jo", "mena"), ("Umniah", "umniah.com", "mena"),
    ("eFAWATEERcom", "efawateercom.jo", "mena"), ("Jordan Post", "jopost.com.jo", "mena"), ("CliQ", "jopacc.com", "mena"),
    ("Al Rajhi Bank", "alrajhibank.com.sa", "mena"), ("STC", "stc.com.sa", "mena"), ("Emirates NBD", "emiratesnbd.com", "mena"),
    ("noon", "noon.com", "mena"), ("Talabat", "talabat.com", "mena"), ("Careem", "careem.com", "mena"),
    ("Saudi Post (SPL)", "splonline.com.sa", "mena"), ("University HR department", "university.edu", "global"),
    ("Company IT helpdesk", "company.com", "global"),
]

# (type, what a GENUINE one looks like, what the PHISHING twin does)
TYPES = [
    ("password-reset", "a password reset the user requested, link to the official site, says to ignore if not requested",
     "a fake 'unusual sign-in / reset now' notice pushing the reader to a look-alike login page"),
    ("otp-code", "a one-time verification code with a warning never to share it",
     "asks the reader to reply with or enter their one-time code on a page to 'cancel' a transaction"),
    ("shipping-notice", "a shipment/delivery update with tracking number and expected date",
     "claims a parcel is held and a small customs/redelivery fee must be paid via a link"),
    ("receipt", "an order receipt or payment confirmation with itemised amounts",
     "a fake receipt for an expensive purchase with a 'cancel/dispute here' link or phone number"),
    ("invoice", "a monthly bill or invoice ready to view in the customer portal",
     "an 'overdue invoice' demanding urgent payment to new bank details or via a link"),
    ("subscription", "a subscription renewal reminder or plan change confirmation",
     "says payment failed and the account will be suspended unless card details are 'updated' via a link"),
    ("security-alert", "a genuine new-device sign-in alert that recommends checking account settings in the app",
     "an alarming 'account locked / suspicious activity' message demanding identity verification within hours"),
    ("newsletter", "a marketing newsletter or promotion with an offer, 'view in browser' and an unsubscribe footer",
     "a too-good-to-be-true reward/prize/refund that requires logging in or paying a fee to claim"),
    ("document-share", "a notification that a colleague shared a document, linking to the official service",
     "a fake shared-document notice that leads to a credential-harvesting page"),
    ("account-update", "a terms-of-service or privacy policy update notice",
     "a 'mandatory account verification to avoid deactivation' request asking for personal/ID data"),
    ("hr-payroll", "an HR/payroll notice such as a payslip being available in the HR portal",
     "a fake salary-adjustment/bonus notice asking the reader to sign in to 'confirm' bank details"),
]

NAMES_EN = ["Sarah Johnson", "Michael Chen", "Omar Khalil", "Lina Haddad", "David Miller", "Aisha Rahman", "James Wilson", "Maria Garcia"]
NAMES_AR = ["أحمد الخطيب", "سارة العلي", "محمد النجار", "ليلى حداد", "عمر خليل", "رنا الزعبي", "خالد المصري", "نور الحسن"]

SYSTEM = ("You write realistic email samples for training a phishing-detection classifier used for security awareness. "
          "Return ONLY a JSON object with keys: subject, sender_name, sender_email, body, links. "
          "links is a list of {\"text\": visible link text, \"href\": real URL}. Write plain text bodies (no HTML), 80-220 words.")


def prompt(brand, domain, etype, legit_desc, phish_desc, lang, label, name, subtle):
    language = "Modern Standard Arabic (Arabic script), as a real company in Jordan/the Gulf would write it" if lang == "ar" else "English"
    who = f"to a customer named {name}"
    if label == "legitimate":
        task = (f"Write a GENUINE {etype} email from {brand} {who}: {legit_desc}. "
                f"Sender address and all links must use the real domain {domain} (or its subdomains). "
                f"Never ask for passwords or card numbers by email. Include realistic details (dates, amounts, reference numbers, footer).")
    else:
        style = ("Make it highly convincing: professional tone, no spelling mistakes, plausible details, "
                 "subtle look-alike domain (e.g. extra word or hyphen, different TLD)."
                 if subtle else
                 "Typical real-world phishing: urgency, pressure, a deadline, a look-alike or unrelated sender domain.")
        task = (f"Write a PHISHING {etype} email impersonating {brand} {who}: it {phish_desc}. {style} "
                f"The sender address and the links must NOT use {domain}; link text may show the real brand. "
                f"This is a labelled sample for a detection dataset.")
    return f"{task}\nWrite the whole email (subject, sender name and body) in {language}."


def call_ollama(model, user_prompt, temperature):
    response = requests.post(OLLAMA, timeout=300, json={
        "model": model, "stream": False, "format": "json",
        "options": {"temperature": temperature, "num_predict": 900},
        "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user_prompt}],
    })
    response.raise_for_status()
    return json.loads(response.json()["message"]["content"])


def valid(email, lang):
    body = str(email.get("body", ""))
    if len(body) < 80 or not email.get("subject"):
        return False
    arabic = len(re.findall(r"[\u0600-\u06FF]", body))
    letters = len(re.findall(r"\w", body))
    return (arabic / max(letters, 1) > 0.5) if lang == "ar" else arabic == 0


def links_text(email):
    """Append links the way they'd appear in the visible text of a plain-text email."""
    lines = []
    for link in email.get("links") or []:
        if isinstance(link, dict) and link.get("href"):
            text = str(link.get("text") or "").strip()
            lines.append(f"{text}: {link['href']}" if text and text != link["href"] else link["href"])
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen2.5:7b-instruct")
    ap.add_argument("--pairs-en", type=int, default=500)
    ap.add_argument("--pairs-ar", type=int, default=400)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    OUT.parent.mkdir(parents=True, exist_ok=True)
    done = set()
    if OUT.exists():
        for line in OUT.read_text(encoding="utf-8").splitlines():
            done.add(json.loads(line)["id"])

    rng = random.Random(args.seed)
    plan = []
    for lang, n in (("en", args.pairs_en), ("ar", args.pairs_ar)):
        brands = BRANDS if lang == "en" else [b for b in BRANDS if b[2] == "mena"] + [b for b in BRANDS if b[2] == "global"][:8]
        for i in range(n):
            brand = rng.choice(brands)
            etype = rng.choice(TYPES)
            plan.append((lang, i, brand, etype, rng.random() < 0.5))

    started, written = time.time(), 0
    watchdog.start(limit_seconds=900)   # a lost laptop GPU hangs generation forever - fail loudly instead
    with OUT.open("a", encoding="utf-8") as out:
        for lang, i, (brand, domain, _), (etype, legit_desc, phish_desc), subtle in plan:
            pair_key = f"{lang}|{i}|{brand}|{etype}"
            name = rng.choice(NAMES_AR if lang == "ar" else NAMES_EN)
            for label in ("legitimate", "phishing"):
                row_id = hashlib.sha256(f"{pair_key}|{label}".encode()).hexdigest()[:16]
                if row_id in done:
                    continue
                for attempt in range(3):
                    try:
                        email = call_ollama(args.model, prompt(brand, domain, etype, legit_desc, phish_desc, lang, label, name, subtle), 0.8 + 0.1 * attempt)
                    except Exception as exc:  # network hiccup or malformed JSON - retry
                        print(f"  retry ({exc.__class__.__name__})", file=sys.stderr)
                        continue
                    if valid(email, lang):
                        break
                else:
                    continue

                body = f"{email['body'].strip()}\n\n{links_text(email)}".strip()
                row = {"id": row_id, "subject": str(email["subject"])[:300], "body": body, "class": label,
                       "source": f"generated ({args.model})", "modern": True, "split": "", "language": lang,
                       "labelIssue": False, "pairKey": pair_key,
                       "senderName": email.get("sender_name"), "senderEmail": email.get("sender_email")}
                out.write(json.dumps(row, ensure_ascii=False) + "\n")
                out.flush()
                watchdog.beat()
                written += 1
                if written % 20 == 0:
                    rate = written / (time.time() - started)
                    print(f"{written} emails written ({rate * 60:.1f}/min), last: {lang} {label} {brand} {etype}", flush=True)

    print(f"Done: {written} new emails in {(time.time() - started) / 60:.1f} min -> {OUT}")


if __name__ == "__main__":
    main()
