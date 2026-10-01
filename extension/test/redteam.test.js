// Red-team: an attacker who controls the email (HTML body, sender, subject, attachments, thread) vs. the content script.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const safeResult = {
  verdict: "safe", score: 0.04, language: "en", reasons: [], limitations: [],
  breakdown: { content: { evaluated: true, probability: 0.02 }, headers: { score: 0, findings: [] }, links: { score: 0, findings: [] } },
};
const phishingResult = { ...safeResult, verdict: "phishing", score: 0.97, reasons: ["Link goes to a raw IP address"] };

beforeAll(() => {
  // The banner uses a closed shadow root; open it so the test can read what the user would see.
  const attach = Element.prototype.attachShadow;
  Element.prototype.attachShadow = function (init) { return attach.call(this, { ...init, mode: "open" }); };

  globalThis.importScripts = () => {};
  globalThis.chrome = {
    runtime: { onMessage: { addListener() {} }, sendMessage: vi.fn() },
    action: { onClicked: { addListener() {} } },
    storage: {
      sync: { get: async (defaults) => ({ ...defaults, fetchRawHeaders: false }) },
      local: { set: async () => {} },
    },
  };
  // The three content scripts share one global scope in Chrome (top-level consts included), so load them as one script.
  const read = (f) => readFileSync(resolve(__dirname, "..", f), "utf8");
  (0, eval)(["src/extract.js", "src/banner.js", "src/content.js"].map(read).join("\n;\n"));
  (0, eval)(read("src/background.js"));
});

beforeEach(() => {
  chrome.runtime.sendMessage = vi.fn(async () => ({ ok: true, result: safeResult }));
});

/** One expanded Gmail message (same structure as test/fixtures/gmail-message.html). */
function message(id, { sender, body, attachments = "" }) {
  return `<div role="listitem"><div class="adn ads" data-message-id="#msg-f:${id}" data-legacy-message-id="${BigInt(id).toString(16)}">
      <h3 class="iw"><span class="gD" email="${sender}" name="Sender">Sender</span></h3>
      <div class="ii gt"><div class="a3s aiL" dir="ltr">${body}</div></div>
      <div class="aQH">${attachments}</div>
    </div></div>`;
}
function openThread(subject, ...messages) {
  document.documentElement.innerHTML =
    `<head><title>Gmail</title></head><body><div role="main"><h2 class="hP">${subject}</h2><div role="list">${messages.join("")}</div></div></body>`;
}
const bannerText = (id) => document.querySelector(`[data-message-id="#msg-f:${id}"] pa-verdict-banner`)?.shadowRoot?.querySelector(".card")?.textContent ?? "(no banner)";

describe("link extraction misses destinations Gmail renders as clickable", () => {
  it("image-map <area href> (supported by Gmail webmail) reaches the link checks", () => {
    openThread("Unusual sign-in activity", message("1001", {
      sender: "security@micros0ft-alerts.com",
      body: `<p>We blocked a sign-in attempt to your account. Review it now.</p>
             <img src="https://ci3.googleusercontent.com/meips/review-button.png" usemap="#m" width="600" height="120">
             <map name="m"><area shape="rect" coords="0,0,600,120" href="https://micros0ft-login.example/verify"></map>`,
    }));
    const email = extractEmail(findOpenMessage());
    expect(email.links.map((l) => l.href)).toContain("https://micros0ft-login.example/verify");
  });

  it("<form action> (supported by Gmail webmail) reaches the link checks", () => {
    openThread("Mailbox quota exceeded", message("1002", {
      sender: "it-support@helpdesk-mail.example",
      body: `<p>Confirm your password to keep receiving email.</p>
             <form action="https://helpdesk-mail.example/collect.php" method="post">
               <input type="email" name="u"><input type="password" name="p"><button type="submit">Confirm</button>
             </form>`,
    }));
    const email = extractEmail(findOpenMessage());
    expect(email.links.map((l) => l.href)).toContain("https://helpdesk-mail.example/collect.php");
  });

  it("300 hidden decoy links can't push the real link out of what is sent", () => {
    const decoys = Array.from({ length: 300 }, (_, i) => `<a href="https://www.microsoft.com/en-us/legal/${i}"></a>`).join("");
    openThread("Your mailbox is almost full", message("1003", {
      sender: "no-reply@microsoft-storage.example",
      body: `<div style="display:none">${decoys}</div>
             <p>Your mailbox is 99% full. Upgrade now to keep receiving email.</p>
             <a href="https://micros0ft-storage.example/upgrade">Upgrade storage</a>`,
    }));
    const email = extractEmail(findOpenMessage());
    expect(email.links).toHaveLength(300);
    expect(email.links.map((l) => l.href)).toContain("https://micros0ft-storage.example/upgrade");
  });
});

describe("attachment names", () => {
  it("a ':' in the file name doesn't cut the extension off", () => {
    openThread("Remittance", message("1101", {
      sender: "accounts@vendor-billing.example",
      body: "Please find the remittance advice attached.",
      attachments: `<span class="aZo" download_url="text/html:Remittance:Advice.html:https://mail.google.com/mail/u/0?ui=2&attid=0.1">
                      <span class="aV3">Remittance:Advice.html</span></span>`,
    }));
    const email = extractEmail(findOpenMessage());
    expect(email.attachments.map((a) => a.name)).toEqual(["Remittance:Advice.html"]);
  });
});

describe("which message gets the verdict", () => {
  it("every expanded message of a thread is analysed, not only the last one", async () => {
    // Attacker sends the phish, then a harmless follow-up in the same thread (same subject + References header)
    // from a clean address. Both are unread, so Gmail opens the thread with both expanded.
    openThread("Invoice INV-2291",
      message("2001", { sender: "billing@paypa1-invoices.com", body: `Your account is on hold. <a href="http://185.22.4.9/pp/login">Pay now</a>` }),
      message("2002", { sender: "j.smith.accounts@gmail.com", body: "Sorry, forgot to say: please treat this as urgent. Thanks, John" }));

    await scan();
    await scan(); // Gmail mutates the DOM constantly; rescans don't change the picture

    const analysed = chrome.runtime.sendMessage.mock.calls.map(([m]) => m.email.senderEmail);
    expect(bannerText("2002")).toContain("No phishing indicators found");   // green banner shown in the thread
    expect(analysed).toContain("billing@paypa1-invoices.com");              // FAILS: the phishing message is never sent
    expect(bannerText("2001")).not.toBe("(no banner)");
  });

  it("a slow verdict for the previous email is not painted onto the email opened next", async () => {
    let finishA;
    chrome.runtime.sendMessage = vi.fn()
      .mockImplementationOnce(() => new Promise((r) => (finishA = r)))                // A: slow (reputation lookups)
      .mockImplementationOnce(async () => ({ ok: true, result: phishingResult }));   // B: fast

    openThread("Lunch?", message("3001", { sender: "newsletter@vendor.example", body: "Our spring catalogue is out." }));
    const scanA = scan();
    await vi.waitFor(() => expect(chrome.runtime.sendMessage).toHaveBeenCalledTimes(1));

    // The user moves on to the next email while A is still being analysed.
    openThread("Your account is suspended", message("3002", {
      sender: "security@paypa1-support.com", body: `Verify within 24 hours. <a href="http://185.22.4.9/pp/login">Verify</a>`,
    }));
    await scan();
    expect(bannerText("3002")).toContain("This email looks like phishing");

    finishA({ ok: true, result: safeResult });   // A's verdict arrives late
    await scanA;
    expect(bannerText("3002")).toContain("This email looks like phishing");   // FAILS: B now shows A's green "safe" banner
  });
});

describe("feedback", () => {
  it("an opted-in 👎 report stays within the API's limits (subject <= 1000 chars)", async () => {
    globalThis.fetch = vi.fn(async () => ({ ok: true, status: 204 }));
    chrome.storage.sync.get = async (defaults) => ({ ...defaults, shareEmailWithFeedback: true });

    // Attacker-chosen 1,200-char subject; the user reports the "safe" verdict as wrong.
    await sendFeedback({
      correct: false,
      result: safeResult,
      email: { subject: "Action required ".repeat(75), senderEmail: "security@paypa1-support.com", body: "Verify now", links: [] },
    });
    const sent = JSON.parse(fetch.mock.calls[0][1].body);
    // FeedbackRequest.Validate: Email.Subject > 1000 -> 400 "Email too large" -> the report is dropped,
    // while the banner has already told the user "Thanks - recorded".
    expect(sent.email.subject.length).toBeLessThanOrEqual(1000);
  });
});
