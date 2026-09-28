# Phishing Email Analyser

A Chrome extension that scores the Gmail message you're reading for phishing and shows the verdict inline. The backend is an ASP.NET Core API that combines a **machine-learned text classifier (ML.NET)** with **rule-based sender and link checks**, and it explains every verdict in plain language.

[![CI/CD](https://github.com/SALEM501jo/phishing-email-analyser/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/SALEM501jo/phishing-email-analyser/actions/workflows/ci-cd.yml)

```
┌──────────── Gmail tab ─────────────┐          ┌──────────── ASP.NET Core API (Docker) ────────────────┐
│ content script                     │          │  POST /api/v1/analyse                                 │
│  • subject, sender, body, links,   │  JSON    │   ├─ Text classifier (ML.NET; EN/AR transformer next)  │
│    attachment NAMES (from the DOM) │ ───────► │   ├─ Sender checks   display name, Reply-To, look-alike│
│  • optional raw headers via        │ (via     │   │                  domains, SPF/DKIM/DMARC/compauth   │
│    Gmail "Show original"           │ service  │   ├─ Link checks     typosquats, homoglyphs, IP URLs,   │
│ service worker                     │ worker)  │   │                  text≠href, hosting platforms       │
│  • decodes QR codes locally (jsQR) │          │   ├─ Attachments     executables, ISO, HTML/SVG, macros,│
│  • calls the API                   │ ◄─────── │   │                  double extensions, RTLO names      │
│ banner (closed shadow DOM, EN/AR)  │ verdict  │   ├─ Obfuscation     mixed-alphabet words ("Pаypal")    │
└────────────────────────────────────┘          │   ├─ Reputation      RDAP domain age, URLhaus/OpenPhish,│
                                                │   │                  optional Safe Browsing; short links│
                                                │   │                  expanded (SSRF-guarded)            │
                                                │   └─ Fusion: noisy-OR → phishing / suspicious / safe    │
                                                └──────────────────────────────────────────────────────────┘
```

## Why several signals

| Signal | What it catches | Why this technique |
|---|---|---|
| **Text classifier** (ML) | Urgency, credential requests, impersonation phrasing, e.g. "verify your account within 24 hours", "kindly update your payment" | These are patterns in free text with endless variants. They're learned from ~7,700 real phishing and fraud emails (3,100 of them from 2022–2026), not written as `if` statements. |
| **Sender checks** (rules) | `PayPal <support@gmail.com>`, `paypa1.com`, Reply-To pointing elsewhere, SPF/DKIM/DMARC/compauth failures | These are crisp, verifiable facts. A rule is exact and explainable, and needs no training data. |
| **Link checks** (rules) | `www.dhl.com` text linking to `dhl-parcel-track.info`, raw IP URLs, `paypal.com.verify.xyz`, homoglyphs, brand pages on `pages.dev` / Google Sites | Same reason: they're deterministic properties of a URL. |
| **Attachments** (rules) | `invoice.pdf.exe`, `.iso`, `.html`/`.svg` fake login pages, macro files, archives whose password is in the email | Judged from **file names only**. Files are never downloaded or opened. |
| **Reputation** (network) | Domains registered days ago, URLs already reported on URLhaus / OpenPhish (and Google Safe Browsing, optional) | Catches attacks whose wording and links *look* normal. |

The signals are fused with a **noisy-OR**: `score = 1 − Π(1 − sᵢ)`. The text signal enters as `0.9·p_text`, and each rule score is itself a noisy-OR of its findings' weights. One strong signal is enough to flag an email, weak signals add up, and a single weak signal can't dominate. The thresholds are **calibrated on held-out modern mail**, not hand-picked: currently ≥ 0.50 for phishing and ≥ 0.25 for suspicious. They're kept within bounds so that no single weak rule can produce a verdict on its own. They ship with the model in `models/model-info.json`, and `appsettings.json` can override them.

### Rules and reputation: design notes
- **Public Suffix List, including its PRIVATE section.** The full PSL is bundled, so `gov.jo` and `com.sa` parse correctly. Its private section lists hosting platforms (`github.io`, `pages.dev`, `web.app`, `square.site`…), so `paypal-login.pages.dev` is treated as its *own* site and never inherits a brand's trust. The first entries of the live OpenPhish feed while this was built were `ledger-com-strts.pages.dev` and `square-nddax-en-us.square.site`.
- **Editable brand catalogue.** `Data/brands.json` holds global brands plus Jordanian and Gulf brands with Arabic names (البنك العربي، أرامكس، الراجحي…). Point `Brands:Path` at your own copy to add a local bank, a university or an employer.
- **Domain age via RDAP.** Newly registered domains are among the strongest phishing indicators. The system is cached, time-boxed (2.5 s) and never blocks the verdict; a failure is reported as "not checked", never as clean. ccTLDs without RDAP (`.jo`, `.sa`, `.io`) show "age unknown".
- **Threat feeds** are downloaded every 30 minutes and matched *locally*, so no URL from your mail is sent to them. Whole-host matches are skipped for brands' own hosts and shared platforms, because attackers also abuse `github.com`.
- **Short-link expansion is an SSRF surface, and is treated as one.**
  - It only contacts known shorteners and reads the `Location` header.
  - It **stops before the destination**, so the attacker's server is never contacted and never learns the email was opened.
  - Private, loopback, link-local (incl. cloud metadata `169.254.169.254`), CGNAT and multicast addresses are refused **at connect time**, on the address actually dialled. That also defeats DNS rebinding.
  - HEAD only, 5 hops, 3 s.
- **QR codes ("quishing")** are decoded **in the browser**, so images never leave the machine. Only images Gmail itself serves are read, never the sender's servers, where an image fetch (a tracking pixel) would confirm the email was opened. The vendored jsQR is pinned and checksum-verified (`extension/vendor/README.md`).

**Privacy trade-off.** RDAP lookups (and Safe Browsing, if you enable it) reveal to those services *which domains* appear in your mail, never its content. Everything is switchable in `appsettings.json` → `Reputation`.

## The ML model

### Data: old and modern, three classes
The classifier sorts mail into three classes: **legitimate / spam / phishing**. Spam is its own class because bulk marketing isn't phishing, and merging the two teaches the model "newsletter = attack".

| Class | Old (1990s–2008) | Modern (2022–2026) |
|---|---|---|
| legitimate | Enron, TREC 05/06/07, CEAS-08, SpamAssassin ham ([Zenodo](https://doi.org/10.5281/zenodo.8339691), CC BY 4.0) | Public mailing-list archives: Python, Fedora, Mailman (21k emails) |
| spam | TREC 05/06/07, CEAS-08, SpamAssassin spam | [untroubled.org](http://untroubled.org/spam/) spam archive 2024–25 (8.1k) |
| phishing | Nazario corpus + Nigerian advance-fee fraud | [phishing_pot](https://github.com/rf-peixoto/phishing_pot) honeypot captures (3.1k English) |

After cleaning, de-duplication and caps there are about 92,000 emails. Everything is English-only for now; non-English mail is kept for later multilingual work. All sources get the same cleaning:
- **Removed corpus fingerprints:** honeypot and spam-trap owner names, Enron internals, mailing-list names and footers, MIME artifacts, and digits (so years can't give away the era).
- **Removed reply history:** quoted replies are stripped to match what Gmail shows.
- **Thread-aware split:** the split is by thread or campaign, so copies of one phishing campaign never land on both sides.

### Honest evaluation: the number that used to be 98.5%
The first version reported **F1 98.5%**. That was measured on test emails from the same old corpora it trained on. I re-evaluated properly:

| Experiment (phishing vs rest, modern 2022–26 test set) | Precision | Recall | F1 | AUC |
|---|---|---|---|---|
| Model trained on **old data only** (the original approach) | 39.6% | **8.0%** | 13.3% | 0.796 |
| **Shipped model** (old + modern, cleaned, calibrated), classifier alone | 80.6% | 48.5% | 60.6% | 0.953 |

The model trained only on old data **misses 92% of today's phishing**, even though it scores 85% F1 on old-era test mail. Phishing language drifts, so a single in-distribution number is misleading.

**End-to-end** measures the full analyser (text + sender + links, fused) on the held-out modern test set. It uses only the fields the extension reads from Gmail, and thresholds tuned on a separate split:

| Verdict | Precision | Recall | False-positive rate on legitimate mail |
|---|---|---|---|
| "phishing" | 97.2% | 62.6% | **0.30%** (13 of 4,341) |
| any warning ("phishing" or "suspicious") | 94.0% | 78.6% | 0.83% |

### Techniques that made the difference
- **Confident learning (label cleaning):** the honeypot also catches marketing, and the spam trap also catches phishing. Each noisy email is scored by a model that never saw it (3-fold, split by campaign). Training emails whose label the model confidently rejects are dropped, 489 in total: 271 "phishing" that were really spam, 72 "spam" that were really phishing, and so on. Test data is never cleaned. (Northcutt et al., 2021, the idea behind *cleanlab*.)
- **Platt calibration:** the phishing probability is rescaled on held-out data so that 0.8 means roughly 80% (Brier score 0.0438 → 0.0422).
- **Threshold calibration:** chosen on a *tune* split, reported on a separate *test* split, never the same data.
- **Model versioning:** each model gets a version such as `2026.09.28-33aa49bb` (date + SHA-256 of the file). It appears in `/health` and in every API response.

### What it learned
- **Phishing-ward:** *verify your, your account, dear customer, action required, password, claim, wallet, reward*, and *"tо"* spelled with a **Cyrillic "о"** (a filter-evasion trick).
- **Spam-ward:** *unsubscribe, % off, save*. A "50% off this weekend" probe now scores spam 48% vs phishing 21%.
- **Explainability:** for each email the API returns the n-grams with the largest `feature × weight` pull towards phishing.

### What the data says about the rules
Measured on modern mail:
- **Rule firing rates:** every rule fires on ≤ 0.3% of legitimate mail. The URL shortener rule fires on 14.7% of phishing.
- **Real headers on 3,120 phishing emails:** only **31%** fail any SPF/DKIM/DMARC/compauth check, and **31% pass all of them**. Email authentication alone would miss most phishing, which is why content and link analysis exist.

### Honest limitations
- **No modern legitimate *transactional or marketing* mail:** there are no newsletters, receipts or password resets from real companies, because no public corpus exists. A genuine "Reset your password" email still scores 75% phishing on text alone. The fix is labelled mail from real inboxes.
- **Legitimate mail is tech-flavoured:** modern legitimate mail comes from developer mailing lists, so its vocabulary leans technical.
- **Phishing recall is 63–79%:** about 1 in 5 modern phishing emails gets no warning. Many are low-effort scams whose text resembles spam.
- **English only:** non-English emails are detected, and the classifier's weight is halved with a stated limitation. A multilingual model (including Arabic) is the next step.

## DOM reading vs. Gmail API

The extension reads the rendered Gmail DOM instead of calling the Gmail API. This avoids OAuth scopes and Google's restricted-scope security review, which is disproportionate for a portfolio demo, and no mailbox data is ever stored server-side. The cost is fragility: Gmail's class names (`h2.hP`, `span.gD`, `div.a3s`) are obfuscated and can change. They're isolated in one object in `extension/src/extract.js`.

**SPF/DKIM/DMARC:** the rendered page doesn't show authentication results. As a best-effort step, the extension fetches Gmail's own *Show original* view (same origin, the user's own session) and sends **only the header block**. The API trusts only the top-most `Authentication-Results` header, which is the one Gmail itself stamped. If that fetch fails, the verdict says auth wasn't checked instead of pretending.

## Extension robustness, privacy and feedback
- **Gmail layout changes.** Each part of the page is found by an ordered list of strategies: Gmail's obfuscated class
  names first, then attributes Gmail relies on functionally (`email=""`, `data-message-id`, `role="main"`), then a
  largest-text heuristic for the body. A test simulates a Gmail release that renames every class and checks that
  extraction still works. If an email is open but can't be read, the banner says **"Gmail layout not recognised"**
  instead of failing silently. *Options → Diagnostics* shows which strategy found each part (no email content), which
  makes a breakage easy to report.
- **Privacy mode.** *Options → metadata only* sends sender, links and attachment names but **no body text**. HTTPS is
  enforced for any server other than localhost, both on the options page and again in the service worker.
- **Feedback loop.** 👍/👎 on the banner sends the verdict, reason codes and model version, enough to track
  false-positive and false-negative rates per model version (`GET /api/v1/feedback/summary`). The email itself is
  included **only** if you opt in, and becomes labelled retraining data. It's stored in SQLite on a Docker volume,
  the only writable path in the read-only container.
- **Tests.** Vitest + jsdom run the real extension scripts in CI against a sanitised Gmail snapshot. They cover
  extraction, the class-rename fallback, **XSS-safe rendering** (a malicious email can't inject HTML into the banner),
  Arabic RTL/bidi, feedback, and the HTTPS guard.
- **Outlook (future work).** The API is client-agnostic: an Outlook add-in would call the same `/api/v1/analyse`.
  It's a second client with its own manifest and Office.js DOM access, so it's out of scope for now.

## Security & privacy decisions
- The API never logs email content, only the verdict, score and counts.
- Only the service worker calls the API, so the API key never touches Gmail's page. Messages are accepted only from `mail.google.com` tabs.
- The banner lives in a **closed shadow root** and uses `textContent` only. Email-derived strings are never parsed as HTML.
- Requests are capped at 512 KB, and fields are validated and length-limited. The API has per-IP rate limiting, an optional `X-Api-Key` compared in constant time, and forwarded headers trusted only from the local proxy.
- The container is read-only, runs as a non-root user with `no-new-privileges`, is limited to 384 MB and ½ CPU, and binds to 127.0.0.1 behind the existing reverse proxy.

## Running locally

```bash
dotnet test                                                     # 149 tests: rules, Arabic, reputation (fake HTTP), SSRF guard, end-to-end API
dotnet run --project src/PhishingAnalyser.Api --launch-profile http   # http://localhost:5080/swagger
```

Load the extension: go to `chrome://extensions`, turn on Developer mode, click **Load unpacked** and choose `extension/`, then open any Gmail message.

Retrain (optional; the trained model is committed in `models/`). This needs ~1 GB of data and ~8 minutes:
```bash
./tools/download-data.sh
dotnet run --project tools/PhishingAnalyser.Trainer -c Release   # writes the model .zip, model-info.json and metrics.json to models/
```

## CI/CD & deployment

`.github/workflows/ci-cd.yml` runs these jobs:
1. **test**: restore, build and test on every push and PR.
2. **extension**: syntax-check the JS, validate the MV3 manifest, and publish the packaged `.zip` as a build artifact.
3. **image**: on `main` or tags, build the Docker image and push it to `ghcr.io/<owner>/phishing-analyser` (tags `latest`, `sha-xxxx`, semver).
4. **deploy**: SSH to the VPS and run `docker compose pull && up -d`, then health-check. This job is opt-in, so add the following first:
   - repository variable `DEPLOY_ENABLED=true`
   - secrets `VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY`
   - optional variable `VPS_APP_DIR`, the folder holding `docker-compose.yml` on the server

On the VPS, put `docker-compose.yml` in that folder, optionally set `PHISHING_API_KEY` in a `.env` next to it, and add a reverse-proxy route such as Caddy's `phishing.example.com { reverse_proxy 127.0.0.1:5080 }`.

## Project layout
```
src/PhishingAnalyser.Core     analysers, brand catalogue, ML pipeline + classifier, scoring
src/PhishingAnalyser.Api      minimal API, validation, rate limiting, API key
tools/PhishingAnalyser.Trainer  corpus loading/cleaning, model comparison, metrics.json
tests/PhishingAnalyser.Tests  xUnit: rules, scoring, WebApplicationFactory end-to-end
extension/                    Chrome MV3 extension
models/                       trained model + metrics
```
