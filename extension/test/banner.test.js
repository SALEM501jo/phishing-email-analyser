import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

beforeAll(() => loadExtensionScripts("src/banner.js"));

let card;
beforeEach(() => {
  document.body.innerHTML = "";
  card = document.createElement("div");
  document.body.append(card);
});

const result = (overrides = {}) => ({
  verdict: "phishing",
  score: 0.93,
  language: "en",
  reasons: ["Link text shows 'www.dhl.com' but actually goes to 'dhl-parcel-track.info'"],
  limitations: [],
  breakdown: {
    content: { evaluated: true, probability: 0.8 },
    headers: { score: 0.4, findings: [] },
    links: { score: 0.6, findings: [] },
  },
  ...overrides,
});

describe("verdict banner", () => {
  it("never interprets email/API text as HTML (XSS)", () => {
    const attack = `<img src=x onerror="window.pwned=true">Click <b>here</b>`;
    renderInto(card, { status: "done", result: result({ reasons: [attack], limitations: [attack] }) });

    expect(card.querySelector("img")).toBeNull();
    expect(card.querySelector("b")).toBeNull();
    expect(card.textContent).toContain(attack);   // shown literally, as text
    expect(window.pwned).toBeUndefined();
  });

  it("renders Arabic results right-to-left and isolates embedded domains", () => {
    renderInto(card, {
      status: "done",
      result: result({ language: "ar", reasons: ["نطاق المرسل ينتحل صفة Arab Bank: النطاق 'arabbank-jo-verify.com' ليس تابعًا لها"] }),
    });
    expect(card.getAttribute("dir")).toBe("rtl");
    expect(card.textContent).toContain("هذه الرسالة تبدو محاولة تصيّد احتيالي");
    const isolated = [...card.querySelectorAll("li bdi")].map((b) => b.textContent);
    expect(isolated).toContain("Arab Bank");
    expect(isolated.some((t) => t.includes("arabbank-jo-verify.com"))).toBe(true);
  });

  it("shows English results left-to-right without bidi wrapping", () => {
    renderInto(card, { status: "done", result: result() });
    expect(card.getAttribute("dir")).toBe("ltr");
    expect(card.querySelector("bdi")).toBeNull();
    expect(card.textContent).toContain("risk 93/100");
  });

  it("sends 👍/👎 feedback once and thanks the user", () => {
    const onFeedback = vi.fn();
    const state = { status: "done", result: result(), onFeedback };
    renderInto(card, state);

    const [yes, no] = card.querySelectorAll(".feedback button");
    no.click();
    expect(onFeedback).toHaveBeenCalledWith(false);
    expect(card.querySelector(".feedback button")).toBeNull();
    expect(card.textContent).toContain("Thanks");

    renderInto(card, state);   // Gmail re-render: still answered, no buttons again
    expect(card.querySelector(".feedback button")).toBeNull();
    expect(onFeedback).toHaveBeenCalledTimes(1);
  });

  it("explains an unreadable Gmail layout instead of failing silently", () => {
    renderInto(card, { status: "unsupported", language: "en" });
    expect(card.textContent).toContain("Gmail's layout wasn't recognised");
  });

  it("tells the user when privacy mode kept the text in the browser", () => {
    renderInto(card, { status: "done", result: result(), metadataOnly: true });
    expect(card.textContent).toContain("Privacy mode");
  });
});
