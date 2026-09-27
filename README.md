# Phishing Email Analyser

A Chrome extension that scores the Gmail message you're reading for phishing and shows the verdict inline. The backend is an ASP.NET Core API that combines a **machine-learned text classifier (ML.NET)** with **rule-based sender and link checks**, and it explains every verdict in plain language.

![CI/CD](../../actions/workflows/ci-cd.yml/badge.svg)

```
┌──────────── Gmail tab ────────────┐          ┌──────────── ASP.NET Core API (Docker) ─────────────┐
│ content script                    │          │  POST /api/v1/analyse                              │
│  • reads subject/sender/body/links│  JSON    │   ├─ Text classifier  (ML.NET, TF-IDF + logistic)  │
│    from the DOM                   │ ───────► │   ├─ Sender checks    (display name, Reply-To,     │
│  • optional: raw headers via      │ (via     │   │                    look-alike domains, SPF/     │
│    Gmail "Show original"          │ service  │   │                    DKIM/DMARC from headers)     │
│  • renders verdict banner         │ worker)  │   ├─ Link checks      (typosquats, IP URLs, text≠href│
│    (closed shadow DOM)            │ ◄─────── │   │                    shorteners, risky TLDs)      │
└───────────────────────────────────┘ verdict  │   └─ Fusion: noisy-OR → phishing / suspicious / safe│
                                               └─────────────────────────────────────────────────────┘
```

## Why three signals

| Signal | What it catches | Why this technique |
|---|---|---|
| **Text classifier** (ML) | Urgency, credential requests, impersonation phrasing, e.g. "verify your account within 24 hours", "kindly update your payment" | These are patterns in free text with endless variants. They're learned from ~1,500 real phishing emails, not written as `if` statements. |
| **Sender checks** (rules) | `PayPal <support@gmail.com>`, `paypa1.com`, Reply-To pointing elsewhere, SPF/DKIM/DMARC failures | These are crisp, verifiable facts. A rule is exact and explainable, and needs no training data. |
| **Link checks** (rules) | `www.dhl.com` text linking to `dhl-parcel-track.info`, raw IP URLs, `paypal.com.verify.xyz`, homoglyphs | Same reason: they're deterministic properties of a URL. |

The signals are fused with a **noisy-OR**: `score = 1 − (1 − 0.9·p_text)(1 − s_sender)(1 − s_links)`, where each rule score is itself a noisy-OR of its findings' weights. One strong signal is enough to flag an email, weak signals add up, and a single weak signal can't dominate. Thresholds are ≥ 0.7 for phishing and ≥ 0.4 for suspicious. You can change them in `appsettings.json`.

## The ML model

- **Data:** *Phishing Email Curated Datasets* (Champa et al., Zenodo, [doi:10.5281/zenodo.8339691](https://doi.org/10.5281/zenodo.8339691), CC BY 4.0).
  - Phishing: Nazario corpus.
  - Legitimate: raw Enron mail from `Nazario_5` plus SpamAssassin *ham*.
  - After de-duplication there are 6,776 emails (1,525 phishing, 5,251 legitimate), split 80/20 with stratification.
- **Pipeline (ML.NET):** normalise → word 1–2-grams (TF-IDF) + character 3-grams → L2 normalise → `SdcaLogisticRegression`. The trainer compares four candidates and keeps the one with the best F1:

| Candidate | Accuracy | Precision | Recall | F1 | AUC |
|---|---|---|---|---|---|
| words + SDCA | 99.19% | 98.68% | 97.70% | 98.19% | 0.997 |
| words + L-BFGS | 97.27% | 99.63% | 88.20% | 93.57% | 0.997 |
| **words + char-3grams + SDCA** ✅ | **99.34%** | 98.37% | **98.69%** | **98.53%** | 0.996 |
| words + char-3grams + L-BFGS | 98.23% | 99.30% | 92.79% | 95.93% | 0.996 |

- **Explainability:** the model is linear, so for each email the API reports the n-grams with the largest `feature × weight` contribution. The banner can then say *why*, e.g. "strongest cues: "parcel", "payment", "update your"".
- **What it learned:** the top phishing-ward terms include *account, dear, payment, verify, kindly, mailbox, update, click, below*. It also learned *"tо"* spelled with a **Cyrillic "о"**, a real obfuscation trick used to dodge keyword filters.

### Leakage I found and removed
The first model scored well, but its top features included `=utf` and `url <link> date`. Those are **corpus artifacts**, not language: undecoded MIME subjects appear only in the phishing dump, and RSS-digest lines appear only in SpamAssassin ham. The trainer now strips:
- MIME encoded-words and RSS-digest lines;
- mailbox-owner names (`jose@monkey.org`, Enron internals);
- digits, so the model can't tell 2002-era ham from 2015-era phishing by the years in them.

It also drops the pre-tokenised `Enron.csv` for the same reason. I chose to accept slightly lower headline numbers in exchange for a model that learns phishing language.

### Honest limitations
- The legitimate corpus is old (2001–2002 corporate and mailing-list mail). Modern marketing newsletters look different, so they can get a higher text score than they deserve. The rule-based checks and the "suspicious" middle band soften this. The real fix is adding modern ham, such as your own labelled inbox.
- Spam is **not** phishing. SpamAssassin spam is deliberately excluded, so the model isn't a spam filter.
- The model is English-centric. Arabic phishing is a clear next step.

## DOM reading vs. Gmail API

The extension reads the rendered Gmail DOM instead of calling the Gmail API. This avoids OAuth scopes and Google's restricted-scope security review, which is disproportionate for a portfolio demo, and no mailbox data is ever stored server-side. The cost is fragility: Gmail's class names (`h2.hP`, `span.gD`, `div.a3s`) are obfuscated and can change. They're isolated in one object in `extension/src/extract.js`.

**SPF/DKIM/DMARC:** the rendered page doesn't show authentication results. As a best-effort step, the extension fetches Gmail's own *Show original* view (same origin, the user's own session) and sends **only the header block**. The API trusts only the top-most `Authentication-Results` header, which is the one Gmail itself stamped. If that fetch fails, the verdict says auth wasn't checked instead of pretending.

## Security & privacy decisions
- The API never logs email content, only the verdict, score and counts.
- Only the service worker calls the API, so the API key never touches Gmail's page. Messages are accepted only from `mail.google.com` tabs.
- The banner lives in a **closed shadow root** and uses `textContent` only. Email-derived strings are never parsed as HTML.
- Requests are capped at 512 KB, and fields are validated and length-limited. The API has per-IP rate limiting, an optional `X-Api-Key` compared in constant time, and forwarded headers trusted only from the local proxy.
- The container is read-only, runs as a non-root user with `no-new-privileges`, is limited to 384 MB and ½ CPU, and binds to 127.0.0.1 behind the existing reverse proxy.

## Running locally

```bash
dotnet test                                                     # 47 tests: rules, scoring, end-to-end API with the real model
dotnet run --project src/PhishingAnalyser.Api --launch-profile http   # http://localhost:5080/swagger
```

Load the extension: go to `chrome://extensions`, turn on Developer mode, click **Load unpacked** and choose `extension/`, then open any Gmail message.

Retrain (optional; the trained model is committed in `models/`):
```bash
./tools/download-data.sh
dotnet run --project tools/PhishingAnalyser.Trainer -c Release   # writes models/*.zip + metrics.json
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
