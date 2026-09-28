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
  .pending, .error { --bg: #f1f3f4; --edge: #dadce0; --accent: #5f6368; }
`;

const STRINGS = {
  en: {
    pill: { phishing: "phishing", suspicious: "suspicious", safe: "safe", pending: "Scanning", error: "Offline" },
    title: {
      phishing: "This email looks like phishing",
      suspicious: "Be careful with this email",
      safe: "No phishing indicators found",
    },
    pending: "Analysing this email for phishing…",
    error: (m) => `Phishing analyser unavailable: ${m}`,
    risk: (n) => `risk ${n}/100`,
    meta: (t, s, l, auth) => `Text classifier ${t} · Sender checks ${s} · Link checks ${l}${auth ? " · SPF/DKIM/DMARC checked" : ""}`,
  },
  ar: {
    pill: { phishing: "تصيّد", suspicious: "مشبوهة", safe: "آمنة", pending: "جارٍ الفحص", error: "غير متصل" },
    title: {
      phishing: "هذه الرسالة تبدو محاولة تصيّد احتيالي",
      suspicious: "توخَّ الحذر مع هذه الرسالة",
      safe: "لم تُرصد مؤشرات تصيّد",
    },
    pending: "جارٍ فحص الرسالة بحثًا عن التصيّد…",
    error: (m) => `محلّل التصيّد غير متاح: ${m}`,
    risk: (n) => `درجة الخطورة ${n}/100`,
    meta: (t, s, l, auth) => `مصنّف النص ${t} · فحص المرسل ${s} · فحص الروابط ${l}${auth ? " · تم فحص SPF/DKIM/DMARC" : ""}`,
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
    node.append(text.slice(last, match.index));
    node.append(el("bdi", null, match[0]));
    last = match.index + match[0].length;
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

  if (state.status === "pending" || state.status === "error") {
    card.className = `card ${state.status}`;
    const head = el("div", "head");
    head.append(el("span", "pill", t.pill[state.status]),
                el("span", "title", state.status === "pending" ? t.pending : t.error(state.message)));
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
    b.content.evaluated ? pct(b.content.probability) : "n/a", pct(b.headers.score), pct(b.links.score), state.usedRawHeaders), rtl));
  for (const note of r.limitations ?? []) body.append(bidiText("div", "meta", `ⓘ ${note}`, rtl));

  card.append(head, bar, body);
}
