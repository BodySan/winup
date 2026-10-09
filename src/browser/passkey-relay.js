// Isolated-world bridge. Browser-owned sender URL is checked again in background.js.
(() => {
  if (window !== window.top) return;
  const active = new Map();
  const send = message => new Promise(resolve => chrome.runtime.sendMessage(message, r => resolve(r || { error: "host_error" })));
  function respond(id, result) {
    document.dispatchEvent(new CustomEvent("winup-passkeys-response", { detail: JSON.stringify({ ...result, requestId: id }) }));
  }
  document.addEventListener("winup-passkeys-request", async event => {
    if (typeof event.detail !== "string" || event.detail.length > 60000) return;
    let request;
    try { request = JSON.parse(event.detail); } catch { return; }
    const id = request.requestId;
    if (!/^[a-f0-9]{32}$/.test(id || "")) return;
    if (request.action === "available") {
      respond(id, await send({ type: "passkeys-settings" })); return;
    }
    if (request.action === "abort") {
      if (!active.has(id)) return;
      active.delete(id); await send({ type: "passkey-cancel", requestId: id }); return;
    }
    if (!["passkeys_create", "passkeys_get"].includes(request.action) || !request.publicKey || active.has(id)) return;
    if (active.size > 0) { respond(id, { error: "NotAllowedError" }); return; }
    const url = location.href;
    active.set(id, url);
    const result = await send({ type: request.action === "passkeys_create" ? "passkey-create" : "passkey-get", requestId: id, publicKey: request.publicKey });
    if (!active.has(id)) return;
    active.delete(id);
    // A native WinUp consent window can occlude Chrome. That does not cancel
    // the credential operation; actual navigation is handled by pagehide/URL.
    if (location.href !== url) { respond(id, { error: "AbortError" }); return; }
    respond(id, result);
  });
  window.addEventListener("pagehide", () => {
    for (const id of active.keys()) send({ type: "passkey-cancel", requestId: id });
    active.clear();
  });
})();
