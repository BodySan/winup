// WinUp — пароли: значок в полях входа и список учётных записей (как у «Паролей iCloud»).
// Скрипт ничего не отправляет сам: только по щелчку пользователя спрашивает у WinUp записи для этого сайта.
(() => {
  if (window.__winupLoaded) return;
  window.__winupLoaded = true;

  const ICON = chrome.runtime.getURL("icon32.png");
  const USER_RE = /login|user|email|e-mail|phone|логин|почт|телефон|account|username|identifier/i;
  const OTP_RE = /otp|totp|2fa|mfa|one.?time|verification|security.?code|sms.?code|код/i;

  // ---------- поиск полей ----------
  function visible(el) {
    if (!el.isConnected || el.disabled || el.readOnly) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 40 || r.height < 14) return false;
    const s = getComputedStyle(el);
    return s.visibility !== "hidden" && s.display !== "none" && parseFloat(s.opacity || "1") > 0.1;
  }
  const isText = el => el.tagName === "INPUT" && ["text", "email", "tel", ""].includes((el.getAttribute("type") || "").toLowerCase());
  const hint = el => [el.name, el.id, el.getAttribute("autocomplete"), el.getAttribute("placeholder"), el.getAttribute("aria-label")].join(" ");
  function isOtp(el) {
    if (!isText(el) && !(el.tagName === "INPUT" && el.type === "number")) return false;
    if ((el.getAttribute("autocomplete") || "").includes("one-time-code")) return true;
    const max = parseInt(el.getAttribute("maxlength") || "0", 10);
    return OTP_RE.test(hint(el)) && (max === 0 || max <= 8) && !USER_RE.test(el.name + " " + el.id);
  }
  const scope = el => el.form || el.closest("form") || document;
  const passwords = root => Array.from(root.querySelectorAll("input[type=password]")).filter(visible);
  function userFor(pw) {
    // Ближайшее текстовое поле перед паролем в той же форме.
    const all = Array.from(scope(pw).querySelectorAll("input")).filter(visible);
    const i = all.indexOf(pw);
    for (let j = i - 1; j >= 0; j--) if (isText(all[j]) && !isOtp(all[j])) return all[j];
    return null;
  }
  function isUser(el) {
    if (!isText(el) || isOtp(el)) return false;
    const ac = (el.getAttribute("autocomplete") || "").toLowerCase();
    if (ac.includes("username") || ac === "email") return true;
    if (passwords(scope(el)).some(pw => userFor(pw) === el)) return true;
    return USER_RE.test(hint(el)) && el.type !== "search";
  }
  function kindOf(el) {
    if (el.tagName !== "INPUT") return null;
    if (el.type === "password") return "password";
    if (isOtp(el)) return "otp";
    if (isUser(el)) return "user";
    return null;
  }

  // ---------- слой со значками (shadow DOM: стили сайта не мешают) ----------
  const host = document.createElement("winup-layer");
  host.style.cssText = "position:absolute;left:0;top:0;width:0;height:0;z-index:2147483647;";
  const root = host.attachShadow({ mode: "closed" });
  root.innerHTML = `<style>
    .ic{position:absolute;width:20px;height:20px;cursor:pointer;border-radius:5px;background:#fff url(${ICON}) center/16px no-repeat;
        box-shadow:0 0 0 1px rgba(0,0,0,.12);opacity:.85;transition:opacity .1s}
    .ic:hover{opacity:1;box-shadow:0 0 0 2px #2563eb}
    .dd{position:absolute;min-width:280px;max-width:380px;background:#fff;color:#111;border-radius:10px;font:13px/1.35 -apple-system,"Segoe UI",sans-serif;
        box-shadow:0 8px 28px rgba(0,0,0,.22),0 0 0 1px rgba(0,0,0,.08);overflow:hidden}
    .hd{display:flex;align-items:center;gap:6px;padding:8px 10px;background:#f4f6fa;font-weight:600;font-size:12px;color:#334}
    .hd img{width:16px;height:16px}
    .it{display:block;width:100%;text-align:left;border:0;background:none;padding:8px 12px;cursor:pointer;font:inherit;color:inherit}
    .it:hover,.it:focus{background:#e8efff;outline:none}
    .it b{display:block;font-weight:600}.it span{color:#556;font-size:12px}.it i{color:#a05a00;font-style:normal;font-size:11px}
    .msg{padding:10px 12px;color:#333}
    .bt{margin:0 12px 10px;padding:6px 10px;border:0;border-radius:6px;background:#2563eb;color:#fff;cursor:pointer;font:inherit}
    .sr{display:block;width:calc(100% - 24px);margin:8px 12px;padding:6px 8px;border:1px solid #ccd;border-radius:6px;font:inherit;box-sizing:border-box}
    .ft{border-top:1px solid #eef;padding:2px 0}
  </style>`;
  (document.documentElement || document.body).appendChild(host);

  const icons = new Map(); // input -> значок
  let dd = null, ddFor = null;

  // ---------- защита: вставка только по настоящему щелчку по видимому списку ----------
  // Список должен быть виден целиком (браузер сам проверяет, что его ничто не перекрывает и он не прозрачный:
  // IntersectionObserver v2), простоять на экране не меньше SHOW_MS и получить щелчок от пользователя (isTrusted).
  const SHOW_MS = 500;
  let ddShownAt = 0, ddVisible = false, ddObserver = null;
  function pageLooksNormal() {
    for (const el of [document.documentElement, document.body, host]) {
      if (!el) continue;
      const s = getComputedStyle(el);
      if (parseFloat(s.opacity || "1") < 0.95 || s.visibility === "hidden" || (s.filter && s.filter !== "none") ||
          (s.clipPath && s.clipPath !== "none")) return false;
    }
    return true;
  }
  function watchVisibility(el) {
    if (ddObserver) ddObserver.disconnect();
    ddVisible = false;
    try {
      ddObserver = new IntersectionObserver(es => { for (const e of es) ddVisible = e.isVisible === true; },
        { trackVisibility: true, delay: 100, threshold: [1.0] });
      ddObserver.observe(el);
    } catch (e) { ddObserver = null; }
  }
  function clickAllowed(e) {
    return e.isTrusted && dd && ddVisible && Date.now() - ddShownAt >= SHOW_MS && pageLooksNormal();
  }
  // Фрейм внутри страницы другого сайта: вставка только с подтверждением в окне WinUp.
  function framedByOtherSite() {
    if (window === window.top) return false;
    const a = location.ancestorOrigins;
    if (!a) return true;
    for (let i = 0; i < a.length; i++) if (a[i] !== location.origin) return true;
    return false;
  }

  function place() {
    for (const [el, ic] of icons) {
      if (!el.isConnected) { ic.remove(); icons.delete(el); continue; }
      if (!visible(el)) { ic.style.display = "none"; continue; }
      const r = el.getBoundingClientRect();
      ic.style.display = "block";
      ic.style.left = (r.right + scrollX - 25) + "px";
      ic.style.top = (r.top + scrollY + (r.height - 20) / 2) + "px";
    }
    if (dd && ddFor) {
      const r = ddFor.getBoundingClientRect();
      dd.style.left = (r.left + scrollX) + "px";
      dd.style.top = (r.bottom + scrollY + 4) + "px";
    }
  }

  function scan() {
    for (const el of document.querySelectorAll("input")) {
      if (icons.has(el) || !visible(el)) continue;
      const kind = kindOf(el);
      if (!kind) continue;
      const ic = document.createElement("div");
      ic.className = "ic";
      ic.title = "WinUp — вставить пароль";
      ic.addEventListener("mousedown", e => { e.preventDefault(); e.stopPropagation(); });
      ic.addEventListener("click", e => { e.preventDefault(); e.stopPropagation(); if (e.isTrusted) toggle(el); });
      root.appendChild(ic);
      icons.set(el, ic);
    }
    place();
  }

  // ---------- выпадающий список ----------
  const send = msg => new Promise(res => chrome.runtime.sendMessage(msg, r => res(r || { ok: false, error: "host_error", detail: chrome.runtime.lastError && chrome.runtime.lastError.message })));
  const node = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };

  function close() { if (dd) dd.remove(); if (ddObserver) ddObserver.disconnect(); dd = null; ddFor = null; ddVisible = false; }

  function toggle(el) {
    if (dd && ddFor === el) { close(); return; }
    close();
    ddFor = el;
    dd = node("div", "dd");
    dd.addEventListener("mousedown", e => e.stopPropagation());
    root.appendChild(dd);
    place();
    ddShownAt = Date.now();
    watchVisibility(dd);
    load();
  }

  function frame(children) {
    if (!dd) return;
    dd.textContent = "";
    const hd = node("div", "hd");
    const img = node("img"); img.src = ICON;
    hd.append(img, node("span", null, "WinUp"));
    dd.append(hd, ...children);
  }

  const ERRORS = {
    not_installed: "Расширение ещё не связано с программой. В WinUp откройте: Меню → «Расширение для браузера» → «Подключить».",
    not_running: "WinUp не запущен.",
    locked: "База паролей закрыта.",
    not_paired: "Нажмите значок WinUp на панели браузера и свяжите расширение с программой (один раз).",
    denied: "Отменено в WinUp.",
    not_found: "Запись не найдена — возможно, её удалили.",
    insecure: "Страница открыта без https — пароль от защищённого сайта сюда не вставляется.",
    busy: "В окне WinUp уже открыт вопрос — ответьте на него и попробуйте снова.",
    rate_limited: "Слишком много запросов подряд — подождите минуту.",
    bad_caller: "WinUp не узнал браузер, из которого пришёл запрос (нужен Chrome, Edge, Яндекс Браузер или Brave). Подробности — в журнале на вкладке «Пароли».",
    bad_server: "Канал связи с WinUp занят другой программой. Закройте WinUp и запустите снова; если не поможет — проверьте ПК антивирусом."
  };

  function errorView(r, retry) {
    const kids = [node("div", "msg", ERRORS[r.error] || ("Ошибка: " + (r.detail || r.error)))];
    const btn = (text, fn) => { const b = node("button", "bt", text); b.addEventListener("click", fn); kids.push(b); };
    if (r.error === "not_running") btn("Запустить WinUp", async () => { await send({ type: "launch" }); frame([node("div", "msg", "Запускаю WinUp…")]); setTimeout(retry, 2500); });
    if (r.error === "locked") btn("Открыть базу в WinUp", async () => { await send({ type: "unlock" }); frame([node("div", "msg", "Введите пароль базы в окне WinUp, затем нажмите «Повторить».")]); const b = node("button", "bt", "Повторить"); b.addEventListener("click", retry); dd && dd.appendChild(b); });
    frame(kids);
  }

  async function load() {
    const want = ddFor && kindOf(ddFor);
    frame([node("div", "msg", "Загрузка…")]);
    const r = await send({ type: "list" });
    if (!dd) return;
    if (!r.ok) { errorView(r, load); return; }
    const items = want === "otp" ? r.items.filter(x => x.otp) : r.items;
    const kids = [];
    if (items.length === 0) kids.push(node("div", "msg", want === "otp" ? "Для этого сайта нет записей с кодом 2FA." : "Для этого сайта нет сохранённых паролей."));
    items.forEach(x => kids.push(item(x)));
    const sr = node("input", "sr");
    sr.placeholder = "Поиск во всех записях…";
    let timer = 0;
    sr.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => search(sr.value, ft), 300); });
    sr.addEventListener("keydown", e => e.stopPropagation());
    const ft = node("div", "ft");
    kids.push(sr, ft);
    frame(kids);
  }

  async function search(q, box) {
    box.textContent = "";
    if (q.trim().length < 2) return;
    const r = await send({ type: "search", query: q });
    if (!r.ok) { box.appendChild(node("div", "msg", ERRORS[r.error] || r.error)); return; }
    if (r.items.length === 0) box.appendChild(node("div", "msg", "Ничего не найдено."));
    r.items.forEach(x => box.appendChild(item(x)));
  }

  function item(x) {
    const b = node("button", "it");
    b.append(node("b", null, x.name), node("span", null, x.login || "(без логина)"));
    if (!x.match) b.append(node("i", null, " · другой сайт: " + x.site + " — WinUp спросит подтверждение"));
    else if (x.exact === false) b.append(node("i", null, " · адрес записи: " + x.site + " — WinUp спросит подтверждение"));
    b.addEventListener("click", e => {
      if (!clickAllowed(e)) {
        frame([node("div", "msg", "Список был закрыт или перекрыт страницей — вставка отменена. Щёлкните по значку WinUp ещё раз.")]);
        return;
      }
      fill(x.id, ddFor);
    });
    return b;
  }

  // ---------- вставка ----------
  function setValue(el, v) {
    // Нативный сеттер + события: React/Vue и прочие фреймворки видят значение как введённое руками.
    const proto = el.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, "value").set.call(el, v);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  async function fill(id, field) {
    const context = fillContext(field);
    if (!context) return;
    frame([node("div", "msg", "Запрашиваю у WinUp…")]);
    const r = await send({ type: "fill", id, framed: framedByOtherSite() });
    if (!r.ok) { if (dd) errorView(r, () => fill(id, field)); return; }
    if (!contextValid(context)) {
      discard(r);
      frame([node("div", "msg", "Страница или поле входа изменились — вставка отменена. Выберите запись снова.")]);
      return;
    }
    const applied = apply(r, context);
    discard(r);
    if (!applied) { frame([node("div", "msg", "Поле входа изменилось — вставка отменена.")]); return; }
    close();
  }

  function fillContext(field) {
    if (!field || !visible(field) || !kindOf(field)) return null;
    const form = field.form;
    const sc = scope(field), kind = kindOf(field);
    const pw = kind === "otp" ? null : (kind === "password" ? field : passwords(sc)[0] || null);
    const user = kind === "otp" ? null : (kind === "user" ? field : pw ? userFor(pw) : null);
    const otp = kind === "otp" ? field : Array.from(sc.querySelectorAll("input")).find(e => visible(e) && isOtp(e)) || null;
    return { url: location.href, field, kind, form, action: form ? form.action : null, pw, user, otp,
      targets: [pw, user, otp].filter(Boolean).map(el => ({ el, type: el.type, form: el.form })) };
  }
  function contextValid(c) {
    return location.href === c.url && visible(c.field) && kindOf(c.field) === c.kind &&
      c.field.form === c.form && (!c.form || c.form.action === c.action) &&
      c.targets.every(t => visible(t.el) && t.el.type === t.type && t.el.form === t.form) &&
      (c.kind === "otp" || (c.kind === "password" ? c.field : passwords(scope(c.field))[0] || null) === c.pw) &&
      (c.kind !== "password" || userFor(c.field) === c.user);
  }
  function discard(r) { if (r) { r.password = r.login = r.otp = ""; } }

  function apply(r, c) {
    if (!contextValid(c)) return false;
    const { pw, user, otp } = c;
    if (c.kind === "otp") { if (r.otp) setValue(c.field, r.otp); return true; }
    if (user && r.login) setValue(user, r.login);
    // input/change handlers may synchronously replace the form or navigate.
    if (!contextValid(c)) return false;
    if (pw && r.password) setValue(pw, r.password);
    if (!contextValid(c)) return false;
    if (otp && r.otp) setValue(otp, r.otp);
    const last = pw || user || c.field;
    if (last) last.focus();
    return true;
  }

  // Вставка из всплывающего окна расширения — только в верхнем фрейме вкладки.
  chrome.runtime.onMessage.addListener((msg, sender, reply) => {
    if (!msg || !["fillFromPopup", "otpFromPopup"].includes(msg.type) || sender.id !== chrome.runtime.id || window !== window.top) return;
    const act = document.activeElement;
    const otpOnly = msg.type === "otpFromPopup";
    const field = otpOnly ? (act && isOtp(act) ? act : Array.from(document.querySelectorAll("input")).find(e => visible(e) && isOtp(e))) :
      (act && kindOf(act) ? act : (passwords(document)[0] || Array.from(document.querySelectorAll("input")).find(e => visible(e) && isUser(e)) || null));
    if (!field) { reply({ ok: false, error: "no_field" }); return; }
    const context = fillContext(field);
    if (!context) { reply({ ok: false, error: "no_field" }); return; }
    send({ type: otpOnly ? "otp-fill" : "fill", id: msg.id }).then(r =>
    {
      if (r.ok && !contextValid(context)) { discard(r); reply({ ok: false, error: "page_changed" }); return; }
      if (r.ok && !apply(r, context)) { discard(r); reply({ ok: false, error: "page_changed" }); return; }
      // The popup needs only the outcome, never the credentials.
      const outcome = { ok: !!r.ok, error: r.error, detail: r.detail };
      discard(r);
      reply(outcome);
    });
    return true;
  });

  // Щелчок вне нашего слоя закрывает список (внутри закрытого shadow DOM путь события содержит только host).
  document.addEventListener("mousedown", e => { if (!e.composedPath().includes(host)) close(); }, true);
  document.addEventListener("keydown", e => { if (e.key === "Escape") close(); }, true);
  addEventListener("scroll", place, true);
  addEventListener("resize", place);
  let pending = 0;
  new MutationObserver(() => { if (!pending) pending = setTimeout(() => { pending = 0; scan(); }, 400); })
    .observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["type", "style", "class", "hidden"] });
  setInterval(place, 1000);
  scan();
})();
