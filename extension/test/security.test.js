import { beforeAll, describe, expect, it } from "vitest";

// background.js is a service worker: stub the worker/extension globals it touches at load time.
beforeAll(() => {
  globalThis.importScripts = () => {};
  globalThis.chrome = { runtime: { onMessage: { addListener() {} } }, action: { onClicked: { addListener() {} } } };
  loadExtensionScripts("src/background.js", "src/content.js");
});

describe("email content only travels over HTTPS", () => {
  it.each(["https://phishing.example.com", "http://localhost:5080", "http://127.0.0.1:5080"])("allows %s", (url) => {
    expect(() => assertSecure(url)).not.toThrow();
  });

  it.each(["http://phishing.example.com", "http://192.168.1.20:5080", "ftp://example.com"])("refuses %s", (url) => {
    expect(() => assertSecure(url)).toThrow(/https/);
  });
});

describe("language guess for the pending banner", () => {
  it("detects Arabic, even with an embedded brand name", () => {
    expect(guessLanguage("عزيزي العميل، شحنتك من Aramex بانتظار الدفع")).toBe("ar");
  });
  it("defaults to English", () => {
    expect(guessLanguage("Your parcel is on hold")).toBe("en");
    expect(guessLanguage("")).toBe("en");
  });
});
