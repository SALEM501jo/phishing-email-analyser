// Arabic bug hunt: every test here FAILS on the current banner.js and documents one confirmed bug.
// The reasons are the exact strings the API produces (LinkAnalyser / HeaderAnalyser / ObfuscationAnalyser / EmailAnalyser).
import { beforeAll, beforeEach, describe, expect, it } from "vitest";

beforeAll(() => loadExtensionScripts("src/banner.js"));

let card;
beforeEach(() => {
  document.body.innerHTML = "";
  card = document.createElement("div");
  document.body.append(card);
});

const arabicResult = (reason) => ({
  verdict: "phishing",
  score: 0.93,
  language: "ar",
  reasons: [reason],
  limitations: [],
  breakdown: {
    content: { evaluated: false, probability: 0 },
    headers: { score: 0.4, findings: [] },
    links: { score: 0.6, findings: [] },
  },
});

/** Text of every isolated (<bdi>) run inside the single rendered reason. */
function isolatedRuns(reason) {
  renderInto(card, { status: "done", result: arabicResult(reason) });
  return [...card.querySelectorAll("li bdi")].map((b) => b.textContent);
}

describe("Arabic banner: one left-to-right phrase must stay in ONE isolate", () => {
  // Each <bdi> is laid out right-to-left as a unit, so a phrase cut into several isolates is shown in reverse order.

  it("keeps a short link with a query string in one piece (shortener-expanded reason)", () => {
    const runs = isolatedRuns("الرابط المختصر https://t.co/AbC123?amp=1 يؤدي فعليًا إلى evil-login.xyz");
    expect(runs).toContain("https://t.co/AbC123?amp=1");   // actual: "https://t.co/AbC123", "amp", "1" -> displayed "1=amp?https://t.co/AbC123"
  });

  it("keeps a homoglyph domain in one piece (punycode reason)", () => {
    // 'аpple.com' with a Cyrillic "а" - what DomainUtils.ToUnicode returns for xn--pple-43d.com
    const runs = isolatedRuns("الرابط يستخدم نطاقًا دوليًا (punycode) يظهر بالشكل 'аpple.com'");
    expect(runs.some((t) => t.includes("аpple.com"))).toBe(true);   // actual: "'" and "pple.com'" - the first letter is left outside
  });

  it("keeps a mixed-script sender name in one piece (mixed-script-sender reason)", () => {
    const runs = isolatedRuns('اسم المرسل "Pаypal" يخلط أحرفًا متشابهة من أبجديات مختلفة لتقليد اسم حقيقي');
    expect(runs.some((t) => t.includes("Pаypal"))).toBe(true);      // actual: '"P' and 'ypal"'
  });

  it("keeps a brand name with parentheses in one piece (brand-display-mismatch reason)", () => {
    const runs = isolatedRuns("اسم المرسل يدّعي أنه X (Twitter) لكن نطاق المرسل هو account-alerts.net");
    expect(runs).toContain("X (Twitter)");                                // actual: "X", "Twitter" -> displayed "(Twitter) X"
  });

  it("keeps the dot of a TLD with the TLD (suspicious-tld reason)", () => {
    const runs = isolatedRuns("الرابط يستخدم امتداد نطاق شائع الاستخدام في التصيّد (.xyz)");
    expect(runs).toContain(".xyz");                                       // actual: "xyz" -> displayed "xyz."
  });
});
