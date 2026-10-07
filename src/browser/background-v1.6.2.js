// WinUp — пароли: фоновая часть расширения.
// Связь с программой — Native Messaging: браузер запускает WinUp.exe (мост), тот передаёт запрос
// в открытое окно WinUp через именованный канал. Каждый запрос подписан токеном сопряжения.
const HOST = "ru.winup.browser";

function native(msg) {
  return new Promise(resolve => {
    try {
      chrome.runtime.sendNativeMessage(HOST, msg, resp => {
        const err = chrome.runtime.lastError;
        if (err) {
          // Мост не прописан в реестре — WinUp ещё не подключал браузер (или подключение снято).
          resolve({ ok: false, error: /not found|не найден/i.test(err.message) ? "not_installed" : "host_error", detail: err.message });
        } else resolve(resp || { ok: false, error: "host_error", detail: "пустой ответ" });
      });
    } catch (e) {
      resolve({ ok: false, error: "host_error", detail: String(e) });
    }
  });
}

let pendingToken = null;
async function token() {
  if (pendingToken) return pendingToken;
  pendingToken = (async () => {
    const s = await chrome.storage.local.get("token");
    if (s.token) return s.token;
    const b = new Uint8Array(32);
    crypto.getRandomValues(b);
    const t = Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
    await chrome.storage.local.set({ token: t });
    return t;
  })();
  try { return await pendingToken; } finally { pendingToken = null; }
}

// Код сопряжения: 6 цифр из SHA-256 токена — те же цифры показывает окно WinUp.
async function pairCode(t) {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(t)));
  const n = ((h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3]) >>> 0;
  return String(n % 1000000).padStart(6, "0");
}

function browserName() {
  const ua = navigator.userAgent;
  if (/YaBrowser/.test(ua)) return "Яндекс Браузер";
  if (/Edg\//.test(ua)) return "Microsoft Edge";
  if (/OPR\//.test(ua)) return "Opera";
  if (/Firefox\//.test(ua)) return "Firefox";
  if (/Vivaldi\//.test(ua)) return "Vivaldi";
  if (navigator.brave) return "Brave";
  return "Google Chrome";
}

async function handle(msg) {
  const t = await token();
  switch (msg.type) {
    case "code":
      return { ok: true, code: await pairCode(t) };
    case "passkeys-settings": {
      const settings = await chrome.storage.local.get("passkeysEnabled");
      return { ok: true, enabled: settings.passkeysEnabled !== false };
    }
    case "pair":
      return native({ type: "pair", token: t, browser: browserName() });
    case "status":
    case "unlock":
    case "launch":
      return native({ type: msg.type, token: t });
    case "list":
      return native({ type: "list", token: t, url: msg.url });
    case "search":
      return native({ type: "search", token: t, url: msg.url, query: msg.query || "" });
    case "otp-list":
      return native({ type: "otp-list", token: t, query: msg.query || "" });
    case "otp":
      return native({ type: "otp", token: t, id: msg.id });
    case "otp-copy":
      return native({ type: "otp-copy", token: t, id: msg.id, generation: msg.generation });
    case "otp-fill":
      return native({ type: "otp-fill", token: t, id: msg.id, url: msg.url });
    case "passkey-create":
    case "passkey-get":
    case "passkey-cancel": {
      const settings = await chrome.storage.local.get("passkeysEnabled");
      if (settings.passkeysEnabled === false) return { ok: false, fallback: true };
      return native({ type: msg.type, token: t, url: msg.url, framed: !!msg.framed, requestId: msg.requestId, publicKey: msg.publicKey, unlockIfNeeded: true });
    }
    case "fill":
      return native({ type: "fill", token: t, url: msg.url, id: msg.id, framed: !!msg.framed, requireConfirmation: !!msg.requireConfirmation });
    case "save":
      return native({ type: "save", token: t, url: msg.url, login: msg.login, password: msg.password, framed: !!msg.framed });
    case "login-claim":
    case "login-step":
    case "login-end":
      return native({type:msg.type,token:t,url:msg.url,nonce:msg.nonce,tab:msg.tab,stage:msg.stage,framed:!!msg.framed});
    case "forget":
      await chrome.storage.local.remove("token");
      return { ok: true };
  }
  return { ok: false, error: "bad_request" };
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (!msg || typeof msg !== "object" || typeof msg.type !== "string" || sender.id !== chrome.runtime.id) { reply({ ok: false, error: "bad_request" }); return; }
  // Listing/revealing codes is available only to our popup, never to a website's content script.
  const fromPopup = sender.url === chrome.runtime.getURL("popup.html");
  if(msg.type.startsWith("login-")) {
    if(fromPopup || !sender.tab || sender.frameId!==0 || !sender.url || !loginSession) {reply({ok:false,error:"bad_request"});return;}
    loginMessage(msg,sender).then(reply,()=>reply({ok:false,error:"host_error"}));return true;
  }
  if (["otp", "otp-list", "otp-copy"].includes(msg.type) && !fromPopup) {
    reply({ ok: false, error: "bad_request" }); return;
  }
  if (msg.type.startsWith("passkey-") && (!sender.tab || sender.frameId !== 0)) {
    reply({ ok: false, error: "SecurityError" }); return;
  }
  if(msg.type === "otp-fill" && (!sender.tab || sender.frameId !== 0)) {
    reply({ ok: false, error: "bad_request" }); return;
  }
  if(msg.type === "save" && (!sender.tab || sender.frameId !== 0 || !sender.url?.startsWith("https://") && !/^http:\/\/localhost(?::\d+)?\//.test(sender.url || ""))) {
    reply({ ok: false, error: "insecure" }); return;
  }
  // Адрес страницы для content-скрипта берём у браузера, а не из сообщения: страница не может выдать себя за другой сайт.
  if (sender.tab && !fromPopup) {
    if (!sender.url) { reply({ ok: false, error: "bad_request" }); return; }
    msg = { ...msg, url: sender.url, framed: sender.frameId !== 0 };
  }
  handle(msg).then(reply, () => reply({ ok: false, error: "host_error" }));
  return true; // ответ асинхронный
});

// Only the browser may supply a tab identity and its real origin. Session storage
// keeps expiring random capabilities and public rules; it never holds credentials.
const loginSession=chrome.storage.session;
async function loginMessage(msg,sender) {
  const key="login-tab-"+sender.tab.id;
  const stored=await loginSession.get(key);
  let job=stored[key];
  if(job && Date.now()>job.expiresAt) {await loginSession.remove(key);job=null;}
  if(msg.type==="login-claim" && msg.nonce) {
    if(!/^[0-9a-f]{64}$/.test(msg.nonce)) return {ok:false,error:"bad_request"};
    job={nonce:msg.nonce,tab:String(sender.tab.id),expiresAt:Date.now()+180000};
  }
  if(!job) return {ok:false,error:"not_found"};
  const result=await handle({...msg,nonce:job.nonce,tab:job.tab,url:sender.url,framed:false});
  if(result.ok && msg.type==="login-claim") {job.expiresAt=result.expiresAt;await loginSession.set({[key]:job});}
  if(msg.type==="login-end" || !result.ok && ["locked","expired","not_found","denied","wrong_origin"].includes(result.error)) await loginSession.remove(key);
  return result;
}

chrome.runtime.onConnect?.addListener(port => {
  if (port.name !== "otp-watch" || port.sender?.id !== chrome.runtime.id ||
      port.sender?.url !== chrome.runtime.getURL("popup.html")) { port.disconnect(); return; }
  let host = null, ended = false;
  port.onDisconnect.addListener(() => { ended = true; if (host) host.disconnect(); });
  token().then(t => {
    if (ended) return;
    host = chrome.runtime.connectNative(HOST);
    host.onMessage.addListener(r => { if (!ended) port.postMessage(r); });
    host.onDisconnect.addListener(() => {
      void chrome.runtime.lastError;
      if (!ended) { port.postMessage({ ok: false, error: "not_running" }); port.disconnect(); }
    });
    host.postMessage({ type: "watch", token: t });
  }).catch(() => { if (!ended) port.disconnect(); });
});
