// jsdom has no layout engine, so the few layout-dependent properties the extension reads are approximated here.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

Object.defineProperty(HTMLElement.prototype, "innerText", {
  configurable: true,
  get() { return this.textContent; },
});
// "Visible" = attached to the document and not explicitly hidden.
Object.defineProperty(HTMLElement.prototype, "offsetParent", {
  configurable: true,
  get() { return this.isConnected && !this.closest("[hidden]") ? this.parentElement : null; },
});
// Images: tests set data-w / data-h to simulate their rendered size.
Object.defineProperty(HTMLImageElement.prototype, "naturalWidth", { configurable: true, get() { return Number(this.dataset.w ?? 0); } });
Object.defineProperty(HTMLImageElement.prototype, "naturalHeight", { configurable: true, get() { return Number(this.dataset.h ?? 0); } });

/** Loads extension scripts as classic scripts in the test's global scope, exactly as Chrome would. */
globalThis.loadExtensionScripts = (...files) => {
  for (const file of files) (0, eval)(readFileSync(resolve(__dirname, "..", file), "utf8"));
};

globalThis.loadFixture = (name) => {
  document.documentElement.innerHTML = readFileSync(resolve(__dirname, "fixtures", name), "utf8");
};
