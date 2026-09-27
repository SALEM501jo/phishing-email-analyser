// Verdict banner rendered inside a closed shadow root so Gmail's CSS can't restyle it
// and the page can't read or tamper with its content.
const BANNER_TAG = "pa-verdict-banner";

const BANNER_CSS = `
  :host { all: initial; display: block; margin: 8px 0 14px; font: 13px/1.45 "Google Sans", Roboto, Arial, sans-serif; }
  .card { border-radius: 10px; border: 1px solid var(--edge); background: var(--bg); color: #1f1f1f; overflow: hidden; }
  .head { display: flex; align-items: center; gap: 10px; padding: 10px 14px; cursor: pointer; user-select: none; }
  .pill { font-weight: 700; font-size: 11px; letter-spacing: .06em; text-transform: uppercase; padding: 3px 9px;
          border-radius: 999px; background: var(--accent); color: #fff; }
  .title { font-weight: 600; flex: 1; }
  .score { font-variant-numeric: tabular-nums; color: #444; }
  .chev { transition: transform .15s; color: #666; }
  .open .chev { transform: rotate(90deg); }
  .body { display: none; padding: 0 14px 12px 14px; }
  .open .body { display: block; }
  ul { margin: 4px 0 8px; padding-left: 18px; }
  li { margin: 3px 0; }
  .meta { color: #555; font-size: 12px; }
  .bar { height: 4px; background: rgba(0,0,0,.08); }
  .bar > i { display: block; height: 100%; background: var(--accent); }
  .phishing  { --bg: #fdecea; --edge: #f3b8b1; --accent: #c5221f; }
  .suspicious{ --bg: #fef7e0; --edge: #f5d98b; --accent: #b06000; }
  .safe      { --bg: #e6f4ea; --edge: #a8dab5; --accent: #137333; }
  .pending, .error { --bg: #f1f3f4; --edge: #dadce0; --accent: #5f6368; }
`;

const TITLES = {
  phishing: "This email looks like phishing",
  suspicious: "Be careful with this email",
  safe: "No phishing indicators found",
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

function renderInto(card, state) {
  const wasOpen = card.classList.contains("open");
  card.replaceChildren();

  if (state.status === "pending") {
    card.className = "card pending";
    const head = el("div", "head");
    head.append(el("span", "pill", "Scanning"), el("span", "title", "Analysing this email for phishing…"));
    card.append(head);
    return;
  }

  if (state.status === "error") {
    card.className = "card error";
    const head = el("div", "head");
    head.append(el("span", "pill", "Offline"), el("span", "title", `Phishing analyser unavailable: ${state.message}`));
    card.append(head);
    return;
  }

  const r = state.result;
  card.className = `card ${r.verdict}${wasOpen || r.verdict !== "safe" ? " open" : ""}`;

  const head = el("div", "head");
  head.append(
    el("span", "pill", r.verdict),
    el("span", "title", TITLES[r.verdict] ?? r.verdict),
    el("span", "score", `risk ${Math.round(r.score * 100)}/100`),
    el("span", "chev", "▸"),
  );
  head.addEventListener("click", () => card.classList.toggle("open"));

  const bar = el("div", "bar");
  const fill = el("i");
  fill.style.width = `${Math.round(r.score * 100)}%`;
  bar.append(fill);

  const body = el("div", "body");
  const list = el("ul");
  for (const reason of r.reasons) list.append(el("li", null, reason));
  body.append(list);

  const b = r.breakdown;
  body.append(el("div", "meta",
    `Text classifier ${b.content.evaluated ? Math.round(b.content.probability * 100) + "%" : "n/a"} · ` +
    `Sender checks ${Math.round(b.headers.score * 100)}% · Link checks ${Math.round(b.links.score * 100)}%` +
    (state.usedRawHeaders ? " · SPF/DKIM/DMARC checked" : "")));
  for (const note of r.limitations ?? []) body.append(el("div", "meta", `ⓘ ${note}`));

  card.append(head, bar, body);
}
