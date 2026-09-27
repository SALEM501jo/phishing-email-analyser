// Runs in Gmail's own JS context (world: MAIN). Its only job is to expose Gmail's per-account
// "ik" token so the isolated content script can build the "Show original" URL for raw headers.
(() => {
  const publish = () => {
    const ik = Array.isArray(window.GLOBALS) ? window.GLOBALS[9] : null;
    if (typeof ik === "string" && /^[0-9a-f]{6,16}$/i.test(ik)) {
      document.documentElement.dataset.paIk = ik;
      return true;
    }
    return false;
  };
  if (!publish()) {
    let tries = 0;
    const timer = setInterval(() => (publish() || ++tries > 20) && clearInterval(timer), 500);
  }
})();
