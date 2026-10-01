// Verdict banner rendered inside a closed shadow root so Gmail's CSS can't restyle it
// and the page can't read or tamper with its content. Arabic emails get an Arabic, right-to-left banner.
const BANNER_TAG = "pa-verdict-banner";

const BANNER_CSS = `
  :host { all: initial; display: block; margin: 8px 0 14px; font: 13px/1.45 "Google Sans", Roboto, Arial, sans-serif; }
  .card { border-radius: 10px; border: 1px solid var(--edge); background: var(--bg); color: #1f1f1f; overflow: hidden; }
  .card[dir="rtl"] { font-family: "Noto Naskh Arabic", "Segoe UI", Tahoma, Arial, sans-serif; font-size: 14px; }
  .head { display: flex; align-items: center; gap: 10px; padding: 10px 14px; cursor: pointer; user-select: none; }
  .pill { font-weight: 700; font-size: 11px; letter-spacing: .06em; text-transform: uppercase; padding: 3px 9px;
          border-radius: 999px; background: var(--accent); color: #fff; }
  [dir="rtl"] .pill { letter-spacing: 0; font-size: 12px; }
  .title { font-weight: 600; flex: 1; }
  .score { font-variant-numeric: tabular-nums; color: #444; }
  .chev { transition: transform .15s; color: #666; }
  [dir="rtl"] .chev { transform: scaleX(-1); }
  .open .chev { transform: rotate(90deg); }
  .body { display: none; padding: 0 14px 12px; }
  .open .body { display: block; }
  ul { margin: 4px 0 8px; padding-inline-start: 18px; }
  li { margin: 3px 0; }
  .meta { color: #555; font-size: 12px; }
  .bar { height: 4px; background: rgba(0,0,0,.08); }
  .bar > i { display: block; height: 100%; background: var(--accent); }
  .phishing  { --bg: #fdecea; --edge: #f3b8b1; --accent: #c5221f; }
  .suspicious{ --bg: #fef7e0; --edge: #f5d98b; --accent: #b06000; }
  .safe      { --bg: #e6f4ea; --edge: #a8dab5; --accent: #137333; }
  .pending, .error, .unsupported { --bg: #f1f3f4; --edge: #dadce0; --accent: #5f6368; }
  .feedback { display: flex; gap: 8px; align-items: center; margin-top: 8px; font-size: 12px; color: #555; }
  .feedback button { font: inherit; border: 1px solid #c4c7c5; background: #fff; border-radius: 999px; padding: 2px 10px; cursor: pointer; }
  .feedback button:hover { background: #f1f3f4; }
`;

const STRINGS = {
  en: {
    pill: { phishing: "phishing", suspicious: "suspicious", safe: "safe", pending: "Scanning", error: "Offline", unsupported: "Not checked" },
    title: {
      phishing: "This email looks like phishing",
      suspicious: "Be careful with this email",
      safe: "No phishing indicators found",
    },
    pending: "Analysing this email for phishing…",
    error: (m) => `Phishing analyser unavailable: ${m}`,
    unsupported: "Gmail's layout wasn't recognised, so this email couldn't be checked. Please update the extension (details under Options > Diagnostics).",
    metadataOnly: "Privacy mode: only sender, links and attachment names were checked - the text stayed in your browser.",
    feedbackQuestion: "Was this verdict right?",
    feedbackYes: "👍 Yes",
    feedbackNo: "👎 No",
    feedbackThanks: "Thanks - recorded. Votes measure how often verdicts are right in real use.",
    risk: (n) => `risk ${n}/100`,
    meta: (t, s, l, rep, auth) => `Text classifier ${t} · Sender checks ${s} · Link checks ${l}${rep ? ` · Reputation ${rep}` : ""}${auth ? " · SPF/DKIM/DMARC checked" : ""}`,
  },
  ar: {
    pill: { phishing: "تصيّد", suspicious: "مشبوهة", safe: "آمنة", pending: "جارٍ الفحص", error: "غير متصل", unsupported: "لم يُفحص" },
    title: {
      phishing: "هذه الرسالة تبدو محاولة تصيّد احتيالي",
      suspicious: "توخَّ الحذر مع هذه الرسالة",
      safe: "لم تُرصد مؤشرات تصيّد",
    },
    pending: "جارٍ فحص الرسالة بحثًا عن التصيّد…",
    error: (m) => `محلّل التصيّد غير متاح: ${m}`,
    unsupported: "لم يتم التعرّف على تصميم Gmail، لذلك لم يمكن فحص هذه الرسالة. يرجى تحديث الإضافة (التفاصيل في الخيارات > التشخيص).",
    metadataOnly: "وضع الخصوصية: تم فحص المرسل والروابط وأسماء المرفقات فقط - بقي نص الرسالة في متصفحك.",
    feedbackQuestion: "هل كان هذا الحكم صحيحًا؟",
    feedbackYes: "👍 نعم",
    feedbackNo: "👎 لا",
    feedbackThanks: "شكرًا - تم التسجيل. تقيس الأصوات مدى صحة الأحكام في الاستخدام الفعلي.",
    risk: (n) => `درجة الخطورة ${n}/100`,
    meta: (t, s, l, rep, auth) => `مصنّف النص ${t} · فحص المرسل ${s} · فحص الروابط ${l}${rep ? ` · السمعة ${rep}` : ""}${auth ? " · تم فحص SPF/DKIM/DMARC" : ""}`,
  },
};

function createBanner() {
  const host = document.createElement(BANNER_TAG);
  const shadow = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = BANNER_CSS;
  const card = document.createElement("div");
  shadow.append(style, card);
  host._render = (state) => renderInto(card, state);
  return host;
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text; // textContent only - API/email strings are never parsed as HTML
  return node;
}

/**
 * In right-to-left text, embedded Latin runs (domains, brand names, "SPF/DKIM") get reordered by the bidi
 * algorithm. Wrapping each run in <bdi> isolates it so the Arabic sentence reads in order. DOM-built, no HTML parsing.
 */
function bidiText(tag, className, text, rtl) {
  const node = el(tag, className);
  if (!rtl) {
    node.textContent = text;
    return node;
  }
  const latinRun = /[A-Za-z0-9'"@][\w.\-@/:%'"&]*(?:\s+[A-Za-z0-9][\w.\-@/:%'"&]*)*/g;
  let last = 0;
  for (const match of text.matchAll(latinRun)) {
    // Trailing punctuation belongs to the Arabic sentence, not the isolated run (else "Bank:" shows the colon on the wrong side).
    const run = match[0].replace(/[:;,.!?]+$/, "");
    node.append(text.slice(last, match.index));
    node.append(el("bdi", null, run));
    last = match.index + run.length;
  }
  node.append(text.slice(last));
  return node;
}

/** Language for the banner: the API's answer once known, otherwise a guess from the email text. */
function bannerLanguage(state) {
  const lang = state.result?.language ?? state.language;
  return lang === "ar" ? "ar" : "en";
}

function renderInto(card, state) {
  const wasOpen = card.classList.contains("open");
  const lang = bannerLanguage(state);
  const t = STRINGS[lang];
  card.replaceChildren();
  card.setAttribute("dir", lang === "ar" ? "rtl" : "ltr");
  card.setAttribute("lang", lang);

  if (state.status === "pending" || state.status === "error" || state.status === "unsupported") {
    card.className = `card ${state.status}`;
    const head = el("div", "head");
    const title = { pending: t.pending, error: t.error(state.message), unsupported: t.unsupported }[state.status];
    head.append(el("span", "pill", t.pill[state.status]), el("span", "title", title));
    card.append(head);
    return;
  }

  const r = state.result;
  card.className = `card ${r.verdict}${wasOpen || r.verdict !== "safe" ? " open" : ""}`;

  const head = el("div", "head");
  head.append(
    el("span", "pill", t.pill[r.verdict] ?? r.verdict),
    el("span", "title", t.title[r.verdict] ?? r.verdict),
    el("span", "score", t.risk(Math.round(r.score * 100))),
    el("span", "chev", "▸"),
  );
  head.addEventListener("click", () => card.classList.toggle("open"));

  const bar = el("div", "bar");
  const fill = el("i");
  fill.style.width = `${Math.round(r.score * 100)}%`;
  bar.append(fill);

  const body = el("div", "body");
  const list = el("ul");
  const rtl = lang === "ar";
  for (const reason of r.reasons) list.append(bidiText("li", null, reason, rtl));
  body.append(list);

  const b = r.breakdown;
  const pct = (x) => `${Math.round(x * 100)}%`;
  body.append(bidiText("div", "meta", t.meta(
    b.content.evaluated ? pct(b.content.probability) : "n/a", pct(b.headers.score), pct(b.links.score),
    b.reputation?.evaluated ? pct(b.reputation.score) : null, state.usedRawHeaders), rtl));
  if (state.metadataOnly) body.append(el("div", "meta", `ⓘ ${t.metadataOnly}`));
  for (const note of r.limitations ?? []) body.append(bidiText("div", "meta", `ⓘ ${note}`, rtl));
  if (state.onFeedback) body.append(feedbackRow(t, state));

  card.append(head, bar, body);
}

/** 👍/👎 buttons; after a click (or on re-render once answered) they're replaced by a thank-you line. */
function feedbackRow(t, state) {
  const row = el("div", "feedback");
  if (state.feedbackSent) {
    row.append(el("span", null, t.feedbackThanks));
    return row;
  }
  const answer = (correct) => {
    state.feedbackSent = true;
    Promise.resolve(state.onFeedback(correct)).catch(() => {});
    row.replaceChildren(el("span", null, t.feedbackThanks));
  };
  const yes = el("button", null, t.feedbackYes);
  const no = el("button", null, t.feedbackNo);
  yes.addEventListener("click", (e) => { e.stopPropagation(); answer(true); });
  no.addEventListener("click", (e) => { e.stopPropagation(); answer(false); });
  row.append(el("span", null, t.feedbackQuestion), yes, no);
  return row;
}
