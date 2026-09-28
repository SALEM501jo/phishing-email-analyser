import { beforeAll, describe, expect, it } from "vitest";

beforeAll(() => loadExtensionScripts("src/extract.js"));

describe("reading an email from Gmail's page (current layout)", () => {
  it("extracts subject, sender, body, links and attachments via the primary selectors", () => {
    loadFixture("gmail-message.html");
    const diagnostics = {};
    const open = findOpenMessage(diagnostics);
    const email = extractEmail(open, diagnostics);

    expect(email.subject).toBe("Your parcel is on hold");
    expect(email.senderName).toBe("DHL Express");
    expect(email.senderEmail).toBe("noreply@dhl-parcel-track.info");   // the sender - not the "to me" recipient
    expect(email.body).toContain("unpaid customs fee");
    expect(email.links).toEqual([
      { text: "www.dhl.com", href: "http://dhl-parcel-track.info/pay" },
      { text: "contact", href: "mailto:help@dhl-parcel-track.info" },   // anchors (#top) skipped
    ]);
    expect(email.attachments.map((a) => a.name)).toEqual(["invoice.pdf.exe", "terms.pdf"]);
    expect(diagnostics).toMatchObject({ message: 0, body: 0, sender: 0, subject: 0 });   // all primary strategies
    expect(messageId(open.root)).toBe("msg-f:1812345678901234567");
  });

  it("offers only Gmail-served, QR-sized images for decoding - never the sender's tracking pixel", () => {
    loadFixture("gmail-message.html");
    expect(qrCandidateImages(findOpenMessage().body)).toEqual(["https://ci3.googleusercontent.com/meips/qr-code.png"]);
  });

  it("finds the ik token in the inline GLOBALS script when the main-world script didn't", () => {
    loadFixture("gmail-message.html");
    delete document.documentElement.dataset.paIk;
    expect(gmailIk()).toBe("a1b2c3d4e5");
  });
});

describe("when Gmail renames its obfuscated classes", () => {
  /** Simulates a Gmail release: every obfuscated class name disappears, functional attributes stay. */
  function renameClasses() {
    loadFixture("gmail-message.html");
    for (const el of document.querySelectorAll("[class]")) el.removeAttribute("class");
  }

  it("still reads the email through the attribute-based fallbacks", () => {
    renameClasses();
    const diagnostics = {};
    const open = findOpenMessage(diagnostics);
    const email = extractEmail(open, diagnostics);

    expect(email.subject).toBe("Your parcel is on hold");
    expect(email.senderEmail).toBe("noreply@dhl-parcel-track.info");
    expect(email.body).toContain("unpaid customs fee");
    expect(diagnostics.message).toBeGreaterThan(0);   // a fallback, not the primary selector
    expect(diagnostics.sender).toBeGreaterThan(0);
    expect(diagnostics.body).toBeGreaterThan(0);
  });

  it("the largest-text heuristic picks the body, not the whole message with its header", () => {
    renameClasses();
    for (const el of document.querySelectorAll("[dir]")) el.removeAttribute("dir");   // defeat the dir= fallbacks too
    const diagnostics = {};
    const open = findOpenMessage(diagnostics);
    expect(diagnostics.body).toBe(3);   // the heuristic strategy
    expect(open.body.innerText).toContain("unpaid customs fee");
    expect(open.body.innerText).not.toContain("DHL Express");   // sender header excluded
  });

  it("reports an open email it cannot read, so the user sees 'layout not recognised' instead of nothing", () => {
    document.documentElement.innerHTML = `<body><div role="main"><div data-legacy-message-id="abc"><span>x</span></div></div></body>`;
    expect(findOpenMessage()).toBeNull();
    expect(emailViewOpen()).toBe(true);
  });
});
