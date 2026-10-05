// The public demo page. Everything shown is built with textContent - nothing from the server or the form is parsed as HTML.
const SAMPLES = {
  phish: {
    senderName: "PayPal Security", senderEmail: "service@paypa1-secure-login.com", subject: "Your account has been limited",
    body: "Dear customer,\n\nWe noticed unusual activity on your account and have limited it. You must verify your identity within 24 hours or your account will be permanently suspended.\n\nClick the link below to confirm your password and card details.\n\nPayPal Security Team",
    linkText: "www.paypal.com", linkUrl: "http://185.22.4.9/paypal/login",
  },
  legit: {
    senderName: "Maya Haddad", senderEmail: "maya.haddad@northwind-outdoor.com", subject: "Notes from Tuesday's sprint review",
    body: "Hi team,\n\nThanks for joining the sprint review on Tuesday. A short summary: the search page shipped, the checkout redesign moves to next sprint, and Omar will look into the slow report queries.\n\nThe full notes and the recording are in the team wiki. Next review is on the 20th at 10:00.\n\nBest,\nMaya",
    linkText: "team wiki", linkUrl: "https://wiki.northwind-outdoor.com/sprints/42",
  },
  arabic: {
    senderName: "البنك العربي", senderEmail: "alerts@arabbank-verify.xyz", subject: "تنبيه أمني: تم تعليق حسابك",
    body: "عزيزي العميل،\n\nتم تعليق حسابك مؤقتًا بسبب نشاط غير معتاد. يرجى تحديث بياناتك وكلمة المرور خلال 24 ساعة لتجنب إيقاف الحساب نهائيًا.\n\nاضغط على الرابط التالي لتأكيد بياناتك.\n\nفريق خدمة العملاء",
    linkText: "arabbank.com", linkUrl: "https://arabbank-verify.xyz/login",
  },
};
const FIELDS = ["senderName", "senderEmail", "subject", "body", "linkText", "linkUrl"];
const $ = (id) => document.getElementById(id);
const TEXT = {
  en: { phishing: "This email looks like phishing", suspicious: "Be careful with this email", safe: "No phishing indicators found", risk: (n) => `risk ${n}/100` },
  ar: { phishing: "هذه الرسالة تبدو محاولة تصيّد احتيالي", suspicious: "كن حذرًا مع هذه الرسالة", safe: "لم يُعثر على مؤشرات تصيّد", risk: (n) => `درجة الخطورة ${n}/100` },
};
const PILL = { en: { phishing: "phishing", suspicious: "suspicious", safe: "safe" }, ar: { phishing: "تصيّد", suspicious: "مشبوهة", safe: "آمنة" } };

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function show(kind, build) {
  const box = $("result");
  box.replaceChildren();
  box.className = kind;
  box.removeAttribute("dir");
  build(box);
}

function showError(message) {
  show("error", (box) => box.append(el("span", "pill", "error"), el("span", "title", message)));
}

function showResult(r) {
  const lang = r.language === "ar" ? "ar" : "en";
  show(["phishing", "suspicious", "safe"].includes(r.verdict) ? r.verdict : "error", (box) => {
    box.setAttribute("dir", lang === "ar" ? "rtl" : "ltr");
    box.append(el("span", "pill", PILL[lang][r.verdict] ?? r.verdict), el("span", "title", TEXT[lang][r.verdict] ?? r.verdict),
      el("span", "score", TEXT[lang].risk(Math.round(r.score * 100))));
    const list = el("ul");
    for (const reason of r.reasons ?? []) list.append(el("li", null, reason));
    box.append(list);
    for (const note of r.limitations ?? []) box.append(el("div", "meta", "ⓘ " + note));
    if (r.modelVersion) box.append(el("div", "meta", "model " + r.modelVersion));
  });
}

for (const button of document.querySelectorAll("[data-sample]")) {
  button.addEventListener("click", () => {
    const sample = SAMPLES[button.dataset.sample];
    for (const f of FIELDS) $(f).value = sample[f] ?? "";
    $("result").className = "";
  });
}

$("form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const payload = Object.fromEntries(FIELDS.map((f) => [f, $(f).value]));
  if (!payload.subject.trim() && !payload.body.trim()) return showError("Enter a subject or a body first.");
  $("go").disabled = true;
  try {
    const res = await fetch("/api/v1/demo/analyse", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    if (res.status === 429) return showError("The demo is busy or you've reached its limit. Try again in a minute.");
    if (res.status === 400) return showError("That input is too long for the demo (subject 300, body 5,000 characters).");
    if (!res.ok) return showError(`The server answered ${res.status}.`);
    showResult(await res.json());
  } catch {
    showError("Could not reach the server.");
  } finally {
    $("go").disabled = false;
  }
});
