"""
Generates PAIRED training emails with local open-source LLMs (Ollama).

Why pairs: public data has no modern legitimate transactional mail (receipts, OTPs, bills, bank notices) and no
Arabic mail at all. For each scenario (brand/sender, email type, language, register) we generate BOTH a genuine
email and its malicious twin (phishing, or spam for bulk-marketing scenarios) from the same generator. Both
classes share the generator's writing style, so "sounds AI-written" cannot become a shortcut; the model has to
learn the real differences (credential requests, pressure, payment redirection, look-alike links).

Arabic focus (the first model flagged 14% of realistic Arabic legitimate mail as phishing, because its only Arabic
legitimate data was translated mailing lists): Jordanian/Gulf senders, government e-services, bills, CliQ,
universities, colleagues - in formal MSA, Levantine/Jordanian colloquial and mixed Arabic-English.

Two outputs:
  data/processed/generated.jsonl       training material (split 70/10/20 by scenario in the .NET prep)
  data/processed/generated_test.jsonl  --test-set: written by a DIFFERENT model family (default gemma2:9b), used
                                       only for testing - if the classifier learned one generator's quirks, this
                                       set exposes it.

Throughput: several requests in flight across one or more Ollama servers (e.g. one per GPU on Kaggle T4 x2).
Resumable: re-running skips rows that already exist.

    python ml/generate_pairs.py --model qwen2.5:14b-instruct --pairs-ar 1500 --pairs-en 400 --hosts http://127.0.0.1:11434,http://127.0.0.1:11435 --workers 8
    python ml/generate_pairs.py --test-set --model gemma2:9b --pairs-ar 200 --pairs-en 60
"""
import argparse
import hashlib
import itertools
import json
import random
import re
import sys
import threading
import zlib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

import watchdog

ROOT = Path(__file__).resolve().parent.parent
PROCESSED = ROOT / "data" / "processed"

# (display name, genuine domain, market) - "global" for everyone, "mena" for Arabic-first senders
BRANDS = [
    ("PayPal", "paypal.com", "global"), ("Microsoft 365", "microsoft.com", "global"), ("Apple", "apple.com", "global"),
    ("Google", "google.com", "global"), ("Amazon", "amazon.com", "global"), ("Netflix", "netflix.com", "global"),
    ("DHL Express", "dhl.com", "global"), ("FedEx", "fedex.com", "global"), ("LinkedIn", "linkedin.com", "global"),
    ("DocuSign", "docusign.net", "global"), ("Dropbox", "dropbox.com", "global"), ("Spotify", "spotify.com", "global"),
    ("Coinbase", "coinbase.com", "global"), ("Booking.com", "booking.com", "global"), ("Uber", "uber.com", "global"),
    ("Aramex", "aramex.com", "mena"), ("Arab Bank", "arabbank.jo", "mena"), ("Housing Bank", "hbtf.com", "mena"),
    ("Jordan Kuwait Bank", "jkb.com", "mena"), ("Bank al Etihad", "bankaletihad.com", "mena"),
    ("Cairo Amman Bank", "cab.jo", "mena"), ("Jordan Islamic Bank", "jordanislamicbank.com", "mena"),
    ("Zain Jordan", "jo.zain.com", "mena"), ("Orange Jordan", "orange.jo", "mena"), ("Umniah", "umniah.com", "mena"),
    ("eFAWATEERcom", "efawateercom.jo", "mena"), ("Jordan Post", "jopost.com.jo", "mena"), ("CliQ (JoPACC)", "jopacc.com", "mena"),
    ("JEPCO electricity", "jepco.com.jo", "mena"), ("Miyahuna water", "miyahuna.com.jo", "mena"),
    ("Sanad government app", "sanad.gov.jo", "mena"), ("Income and Sales Tax Department", "istd.gov.jo", "mena"),
    ("Social Security Corporation", "ssc.gov.jo", "mena"), ("University of Jordan", "ju.edu.jo", "mena"),
    ("Jordan University of Science and Technology", "just.edu.jo", "mena"), ("Royal Jordanian", "rj.com", "mena"),
    ("Al Rajhi Bank", "alrajhibank.com.sa", "mena"), ("STC", "stc.com.sa", "mena"), ("Absher", "absher.sa", "mena"),
    ("Emirates NBD", "emiratesnbd.com", "mena"), ("Etisalat (e&)", "etisalat.ae", "mena"), ("Emirates airline", "emirates.com", "mena"),
    ("noon", "noon.com", "mena"), ("Talabat", "talabat.com", "mena"), ("Careem", "careem.com", "mena"),
    ("Saudi Post (SPL)", "splonline.com.sa", "mena"), ("Carrefour", "carrefouruae.com", "mena"),
    ("company HR department", "company.com.jo", "mena"), ("company IT helpdesk", "company.com.jo", "mena"),
]

# (type, what a GENUINE one looks like, what the MALICIOUS twin does, twin label)
TYPES = [
    ("password-reset", "a password reset the user requested, link to the official site, says to ignore if not requested",
     "a fake 'unusual sign-in / reset now' notice pushing the reader to a look-alike login page", "phishing"),
    ("otp-code", "a one-time verification code with a warning never to share it",
     "asks the reader to reply with or enter their one-time code on a page to 'cancel' a transaction", "phishing"),
    ("shipping-notice", "a shipment/delivery update with tracking number and expected date",
     "claims a parcel is held and a small customs/redelivery fee must be paid via a link", "phishing"),
    ("receipt", "an order receipt or payment confirmation with itemised amounts",
     "a fake receipt for an expensive purchase with a 'cancel/dispute here' link or phone number", "phishing"),
    ("bill", "a monthly bill (electricity, water, mobile, internet) with amount, due date and how to pay in the official app or eFAWATEERcom",
     "a 'final notice' threatening disconnection today unless the reader pays through a link with card details", "phishing"),
    ("bank-statement", "a monthly e-statement or card transaction alert, advising to use the official app for details",
     "says the card is blocked for suspicious activity and asks to 'verify' card number, expiry and CVV on a page", "phishing"),
    ("money-transfer", "a CliQ/bank transfer confirmation with amount, alias and reference number",
     "claims an incoming transfer is pending and asks for online-banking login to 'accept' it", "phishing"),
    ("government-service", "a notice from a government e-service (appointment, document ready, tax filing reminder) pointing to the official portal",
     "a fake fine/refund notice asking for national ID number and card details on a look-alike portal", "phishing"),
    ("university", "a university notice (registration dates, exam schedule, e-learning maintenance, fees due in the student portal)",
     "a fake 'mailbox full / student account suspended' notice asking students to log in via a link", "phishing"),
    ("security-alert", "a genuine new-device sign-in alert that recommends checking account settings in the app",
     "an alarming 'account locked / suspicious activity' message demanding identity verification within hours", "phishing"),
    ("document-share", "a notification that a colleague shared a document, linking to the official service",
     "a fake shared-document notice that leads to a credential-harvesting page", "phishing"),
    ("hr-payroll", "an HR/payroll notice such as a payslip being available in the HR portal",
     "a fake salary-adjustment/bonus notice asking the reader to sign in to 'confirm' bank details", "phishing"),
    ("colleague", "an ordinary work email between colleagues (meeting notes, a question about a report, scheduling)",
     "a 'CEO/manager' email asking urgently and secretly to buy gift cards or change a supplier's bank account", "phishing"),
    ("travel", "a flight/hotel booking confirmation or check-in reminder with booking reference",
     "a fake 'booking problem - re-enter your card within 24 hours or lose the reservation' message", "phishing"),
    ("newsletter", "a marketing newsletter or promotion with an offer, 'view in browser' and an unsubscribe footer",
     "unsolicited bulk spam: miracle products, get-rich courses, cheap followers/visas/loans, from an unrelated sender", "spam"),
    ("offer", "a loyalty-programme or seasonal (Ramadan/Eid/White Friday) offer from a store the customer uses",
     "a too-good-to-be-true prize/reward/refund that requires logging in or paying a small fee to claim", "phishing"),
]

REGISTERS = {
    "ar": [("formal", "Modern Standard Arabic (Arabic script), as a real company or institution in Jordan/the Gulf would write it", 0.55),
           ("colloquial", "Jordanian/Levantine colloquial Arabic in Arabic script (e.g. شو، هلق، بدنا، مشان، يعطيك العافية) - natural for short or personal messages", 0.2),
           ("mixed", "Arabic with some English mixed in, as is common in Jordanian workplaces and apps (English brand names, words like 'link', 'account', 'meeting', 'OTP')", 0.25)],
    "en": [("standard", "English", 1.0)],
}

NAMES_EN = ["Sarah Johnson", "Michael Chen", "Omar Khalil", "Lina Haddad", "David Miller", "Aisha Rahman", "James Wilson", "Maria Garcia"]
NAMES_AR = ["أحمد الخطيب", "سارة العلي", "محمد النجار", "ليلى حداد", "عمر خليل", "رنا الزعبي", "خالد المصري", "نور الحسن",
            "يزن العبادي", "هبة القضاة", "فارس المجالي", "دانا الشريف", "مالك الروسان", "سلمى الطراونة"]

SYSTEM = ("You write realistic email samples for training a phishing-detection classifier used for security awareness. "
          "Return ONLY a JSON object with keys: subject, sender_name, sender_email, body, links. "
          "links is a list of {\"text\": visible link text, \"href\": real URL} (may be empty for personal emails). "
          "Write plain text bodies (no HTML). Vary length: some emails are 2-3 lines, others 150-250 words.")


def prompt(brand, domain, etype, legit_desc, bad_desc, bad_label, lang, register_desc, label, name, subtle):
    who = f"to a person named {name}"
    if label == "legitimate":
        task = (f"Write a GENUINE {etype} email from {brand} {who}: {legit_desc}. "
                f"Sender address and all links must use the real domain {domain} (or its subdomains). "
                f"Never ask for passwords or card numbers by email. Include realistic details (dates, amounts, reference numbers, a normal footer).")
    elif bad_label == "spam":
        task = (f"Write an unsolicited bulk SPAM email {who}: {bad_desc}. It is not from {brand}. "
                f"Typical spam: exaggerated claims, many exclamation marks or none, a generic greeting, an unrelated sender domain. "
                f"This is a labelled sample for a detection dataset.")
    else:
        style = ("Make it highly convincing: professional tone, no spelling mistakes, plausible details, "
                 "subtle look-alike domain (extra word or hyphen, different TLD)."
                 if subtle else
                 "Typical real-world phishing: urgency, pressure, a deadline, a look-alike or unrelated sender domain.")
        task = (f"Write a PHISHING {etype} email impersonating {brand} {who}: it {bad_desc}. {style} "
                f"The sender address and the links must NOT use {domain}; link text may show the real brand. "
                f"This is a labelled sample for a detection dataset.")
    return f"{task}\nWrite the whole email (subject, sender name and body) in {register_desc}."


def valid(email, lang, register):
    body = str(email.get("body", ""))
    if len(body) < 40 or not email.get("subject"):
        return False
    arabic = len(re.findall(r"[؀-ۿ]", body))
    letters = len(re.findall(r"\w", body))
    if lang == "en":
        return arabic == 0
    return arabic / max(letters, 1) > (0.3 if register == "mixed" else 0.55)


def links_text(email):
    """Append links the way they appear in the visible text of a plain-text email."""
    lines = []
    for link in email.get("links") or []:
        if isinstance(link, dict) and link.get("href"):
            text = str(link.get("text") or "").strip()
            lines.append(f"{text}: {link['href']}" if text and text != link["href"] else link["href"])
    return "\n".join(lines)


class Ollama:
    """Round-robins requests over one or more Ollama servers (one per GPU on Kaggle)."""

    def __init__(self, hosts, model):
        self._hosts = itertools.cycle(hosts)
        self._lock = threading.Lock()
        self.model = model

    def chat(self, user_prompt, temperature):
        with self._lock:
            host = next(self._hosts)
        response = requests.post(f"{host}/api/chat", timeout=600, json={
            "model": self.model, "stream": False, "format": "json",
            "options": {"temperature": temperature, "num_predict": 1000},
            "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user_prompt}],
        })
        response.raise_for_status()
        return json.loads(response.json()["message"]["content"])


# Round 3: legitimate transactional/promotional mail is where both models failed (an Apple receipt scored >90%
# phishing), so --focus transactional samples these types 3x as often. Each still gets its malicious twin.
TRANSACTIONAL = {"password-reset", "otp-code", "shipping-notice", "receipt", "bill", "bank-statement", "money-transfer",
                 "security-alert", "travel", "newsletter", "offer", "government-service"}
FOCUS_WEIGHT = 3


def build_plan(args, rng):
    plan = []
    for lang, n in (("ar", args.pairs_ar), ("en", args.pairs_en)):
        brands = BRANDS if lang == "en" else [b for b in BRANDS if b[2] == "mena"] * 3 + [b for b in BRANDS if b[2] == "global"]
        registers = REGISTERS[lang]
        for i in range(n):
            brand = rng.choice(brands)
            etype = rng.choices(TYPES, weights=[FOCUS_WEIGHT if args.focus == "transactional" and t[0] in TRANSACTIONAL else 1 for t in TYPES])[0]
            register = rng.choices(registers, weights=[r[2] for r in registers])[0]
            plan.append((lang, i, brand, etype, register, rng.random() < 0.5, rng.choice(NAMES_AR if lang == "ar" else NAMES_EN)))
    # Interleave languages so a time-limited run still yields both.
    counts = {"ar": max(args.pairs_ar, 1), "en": max(args.pairs_en, 1)}
    plan.sort(key=lambda p: p[1] / counts[p[0]])
    return plan


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen2.5:14b-instruct")
    ap.add_argument("--pairs-ar", type=int, default=1500)
    ap.add_argument("--pairs-en", type=int, default=400)
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--hosts", default="http://localhost:11434", help="comma-separated Ollama base URLs")
    ap.add_argument("--workers", type=int, default=4, help="requests in flight (Ollama batches them per server)")
    ap.add_argument("--test-set", action="store_true", help="write generated_test.jsonl (independent generator, test only)")
    ap.add_argument("--focus", choices=["all", "transactional"], default="all")
    ap.add_argument("--max-minutes", type=float, default=0, help="stop cleanly after this long (0 = no limit)")
    args = ap.parse_args()

    out_path = PROCESSED / ("generated_test.jsonl" if args.test_set else "generated.jsonl")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    done = set()
    if out_path.exists():
        done = {json.loads(line)["id"] for line in out_path.read_text(encoding="utf-8").splitlines() if line.strip()}

    # Different scenarios per generator (and for test sets), so two generators never write the same plan.
    rng = random.Random(args.seed + zlib.crc32(args.model.encode()) + (1000 if args.test_set else 0))
    plan = build_plan(args, rng)
    ollama = Ollama([h.strip() for h in args.hosts.split(",") if h.strip()], args.model)
    kind = "test" if args.test_set else "train"
    started = time.time()
    deadline = started + args.max_minutes * 60 if args.max_minutes else None
    write_lock = threading.Lock()
    written = [0]
    watchdog.start(limit_seconds=1200)

    def job(item, label):
        lang, i, (brand, domain, _), (etype, legit_desc, bad_desc, bad_label), (register, register_desc, _), subtle, name = item
        pair_key = f"{kind}|{args.model}|{lang}|{register}|{i}|{brand}|{etype}"
        row_id = hashlib.sha256(f"{pair_key}|{label}|{args.model}".encode()).hexdigest()[:16]
        if row_id in done or (deadline and time.time() > deadline):
            return
        for attempt in range(3):
            try:
                email = ollama.chat(prompt(brand, domain, etype, legit_desc, bad_desc, bad_label, lang, register_desc, label, name, subtle),
                                    0.8 + 0.1 * attempt)
            except Exception as exc:  # timeout / malformed JSON - retry
                print(f"  retry ({exc.__class__.__name__})", file=sys.stderr, flush=True)
                continue
            if valid(email, lang, register):
                break
        else:
            return
        body = f"{str(email['body']).strip()}\n\n{links_text(email)}".strip()
        row = {"id": row_id, "subject": str(email["subject"])[:300], "body": body, "class": label,
               "source": f"generated{'-test' if args.test_set else ''} ({args.model})", "modern": True,
               "split": "test" if args.test_set else "", "language": lang, "labelIssue": False, "pairKey": pair_key,
               "register": register, "emailType": etype,
               "senderName": email.get("sender_name"), "senderEmail": email.get("sender_email")}
        with write_lock:
            with out_path.open("a", encoding="utf-8") as out:
                out.write(json.dumps(row, ensure_ascii=False) + "\n")
            written[0] += 1
            watchdog.beat()
            if written[0] % 25 == 0:
                rate = written[0] / (time.time() - started) * 60
                print(f"{written[0]} emails written ({rate:.1f}/min), last: {lang}/{register} {label} {brand} {etype}", flush=True)

    jobs = [(item, label) for item in plan for label in ("legitimate", item[3][3])]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(job, item, label) for item, label in jobs]):
            future.result()

    print(f"Done: {written[0]} new emails in {(time.time() - started) / 60:.1f} min -> {out_path}")


if __name__ == "__main__":
    main()
