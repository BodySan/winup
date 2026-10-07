// Всплывающее окно расширения: состояние связи, сопряжение, записи для текущей вкладки, поиск.
const main = document.getElementById("main");
const st = document.getElementById("st");
const send = msg => new Promise(res => chrome.runtime.sendMessage(msg, r => res(r || { ok: false, error: "host_error" })));
const node = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
const btn = (text, fn, alt) => { const b = node("button", "bt" + (alt ? " alt" : ""), text); b.addEventListener("click", fn); return b; };
let tab = null;
let epoch = 0, tick = null, watch = null, watchReady = false, generation = null, lastWatch = 0;
let clearSecretView = null;

function show(...kids) {
  epoch++; clearInterval(tick); tick = null;
  if (clearSecretView) { clearSecretView(); clearSecretView = null; }
  main.textContent = ""; main.append(...kids);
}

function watchState() {
  if (watch) return;
  let reportedError = false;
  watch = chrome.runtime.connect({ name: "otp-watch" });
  watch.onMessage.addListener(r => {
    lastWatch = Date.now();
    if (!r.ok || !r.paired || r.state !== "open" || generation !== r.generation) {
      reportedError = true;
      watchReady = false;
      problem({ error: !r.ok ? r.error : !r.paired ? "not_paired" : "locked" });
      return;
    }
    watchReady = true;
    reportedError = false;
  });
  watch.onDisconnect.addListener(() => {
    void chrome.runtime.lastError; watch = null; watchReady = false;
    if (!reportedError) problem({ error: "not_running" });
  });
}

async function start() {
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const r = await send({ type: "status" });
  if (!r.ok) return problem(r);
  st.textContent = r.state === "open" ? "база открыта" : "база закрыта";
  if (!r.paired) return pairView();
  if (r.state !== "open") return problem({ error: "locked" });
  generation = r.generation;
  watchState();
  listView();
}

function problem(r) {
  st.textContent = "";
  switch (r.error) {
    case "not_installed":
      return show(node("div", "msg", "Расширение ещё не связано с программой. В WinUp откройте: Меню → «Расширение для браузера» → «Подключить», затем перезапустите браузер."));
    case "not_running":
      return show(node("div", "msg", "WinUp не запущен."),
        btn("Запустить WinUp", async () => { await send({ type: "launch" }); show(node("div", "msg", "Запускаю…")); setTimeout(start, 2500); }));
    case "locked":
      st.textContent = "база закрыта";
      return show(node("div", "msg", "База паролей закрыта."),
        btn("Открыть базу в WinUp", async () => { await send({ type: "unlock" }); show(node("div", "msg", "Введите пароль базы в окне WinUp."), btn("Повторить", start)); }));
    case "not_paired":
      return pairView();
    case "busy":
      return show(node("div", "msg", "В окне WinUp уже открыт вопрос — ответьте на него."), btn("Повторить", start));
    case "rate_limited":
      return show(node("div", "msg", "Слишком много запросов подряд — подождите минуту."), btn("Повторить", start));
    case "bad_caller":
      return show(node("div", "msg", "WinUp не узнал этот браузер. Проверены Chrome, Edge, Яндекс Браузер, Brave, Opera и Firefox. Подробности — в журнале на вкладке «Пароли»."));
    case "bad_server":
      return show(node("div", "msg", "Канал связи с WinUp занят другой программой. Закройте WinUp и запустите снова; если не поможет — проверьте ПК антивирусом."));
  }
  show(node("div", "msg", "Ошибка связи с WinUp: " + (r.detail || r.error)));
}

async function pairView() {
  const c = await send({ type: "code" });
  show(node("div", "msg", "Свяжите браузер с WinUp (один раз). Нажмите кнопку — в окне WinUp появится такой же код. Если коды совпадают, подтвердите там."),
    node("div", "code", c.code),
    btn("Связать с WinUp", async () => {
      show(node("div", "msg", "Подтвердите в окне WinUp. Код:"), node("div", "code", c.code));
      const r = await send({ type: "pair" });
      if (r.ok) start(); else if (r.error === "denied") show(node("div", "msg", "Связь отклонена в WinUp."), btn("Ещё раз", pairView)); else problem(r);
    }));
}

function item(x) {
  const b = node("button", "it");
  b.append(node("b", null, x.name), node("span", null, x.login || "(без логина)"));
  if (!x.match) b.append(node("i", null, " · другой сайт: " + x.site + " — WinUp спросит подтверждение"));
  b.addEventListener("click", async () => {
    try {
      const r = await chrome.tabs.sendMessage(tab.id, { type: "fillFromPopup", id: x.id });
      if (r && r.ok) window.close();
      else show(node("div", "msg", r && r.error === "no_field" ? "На странице не найдено поле для входа. Щёлкните в поле логина или пароля и попробуйте снова." : "Не удалось вставить: " + ((r && (r.detail || r.error)) || "нет ответа")), btn("Назад", listView, true));
    } catch (e) {
      show(node("div", "msg", "На этой странице вставка недоступна (служебная страница браузера или страница ещё загружается)."), btn("Назад", listView, true));
    }
  });
  if (!x.otp) return b;
  const row = node("div", "entry");
  row.append(b, btn("Код 2FA", () => otpView(x.id), true));
  return row;
}

function navigation() {
  const nav = node("div", "nav");
  nav.append(btn("Пароли", listView, true), btn("Коды 2FA", otpListView, true));
  return nav;
}

async function otpListView() {
  show(navigation(), node("div", "msg", "Загрузка кодов…"));
  const current = epoch;
  const r = await send({ type: "otp-list" });
  if (current !== epoch) return;
  if (!r.ok) return problem(r);
  const search = node("input", "sr"), box = node("div");
  search.placeholder = "Поиск сервиса или аккаунта…";
  function render() {
    box.textContent = "";
    const q = search.value.trim().toLocaleLowerCase();
    const items = r.items.filter(x => (x.name + " " + x.login).toLocaleLowerCase().includes(q));
    for (const x of items) {
      const b = node("button", "it");
      b.append(node("b", null, x.name), node("span", null, x.login || "(без аккаунта)"));
      b.addEventListener("click", () => otpView(x.id)); box.append(b);
    }
    if (!items.length) box.append(node("div", "msg", "Кодов 2FA не найдено."));
    if (r.items.length === 100) box.append(node("div", "msg", "Показаны первые 100 аккаунтов."));
  }
  search.addEventListener("input", render);
  show(navigation(), search, box); render(); search.focus();
}

async function otpView(id) {
  show(navigation(), node("div", "msg", "Получаю код…"));
  const current = epoch;
  if (!watchReady) { show(navigation(), node("div", "msg", "Ожидаю связь с WinUp…"), btn("Повторить", () => otpView(id))); return; }
  const r = await send({ type: "otp", id });
  if (current !== epoch) { if (r) r.otp = ""; return; }
  if (!r.ok) return problem(r);
  if (!watchReady || r.generation !== generation) { r.otp = ""; return problem({ error: "locked" }); }
  const display = node("div", "code"), timer = node("div", "expiry"), feedback = node("div", "msg");
  // Browser and native host share the Windows clock. Account for response delay
  // before switching to the monotonic countdown; never extend an expired code.
  const deadline = performance.now() + Math.max(0, Math.min(r.expiresAt-r.serverTime,r.expiresAt-Date.now()) - 500);
  let secret = r.otp; r.otp = "";
  const copy = btn("Копировать", async () => {
    if (!secret || performance.now() >= deadline || !watchReady) return;
    const result = await send({ type: "otp-copy", id: r.id, generation });
    if (current + 1 !== epoch) return;
    if (!result.ok) { secret = ""; return problem(result); }
    feedback.textContent = "Код скопирован. Буфер очистится через 30 секунд или при блокировке WinUp.";
  });
  const insert = btn("Вставить только код", async () => {
    if (!tab || !/^https:/.test(tab.url || "")) { feedback.textContent = "Откройте HTTPS-сайт."; return; }
    try {
      const result = await chrome.tabs.sendMessage(tab.id, { type: "otpFromPopup", id: r.id });
      if (current + 1 !== epoch) return;
      if (result?.ok) window.close();
      else feedback.textContent = result?.error === "no_field" ? "Щёлкните в поле кода 2FA и повторите." : "Вставка отменена: " + (result?.error || "нет ответа");
    } catch { feedback.textContent = "Вставка на этой странице недоступна."; }
  }, true);
  show(navigation(), node("h3", null, r.name), display, timer, copy, insert, feedback);
  clearSecretView = () => { secret = ""; display.textContent = ""; copy.disabled = true; insert.disabled = true; };
  function update() {
    const left = Math.max(0, Math.ceil((deadline - performance.now()) / 1000));
    if (!watchReady || Date.now() - lastWatch > 7000) { secret = ""; return problem({ error: "not_running" }); }
    display.textContent = left ? secret : "••••••";
    timer.textContent = left ? "Действует ещё " + left + " с" : "Получаю следующий код…";
    copy.disabled = left < 3;
    if (!left) { secret = ""; otpView(r.id); }
  }
  tick = setInterval(update, 250); update();
}

async function listView() {
  if (!tab || !/^https?:/.test(tab.url || "")) {
    return show(navigation(), node("div", "msg", "Откройте сайт, на котором нужно войти."));
  }
  const current = epoch;
  const r = await send({ type: "list", url: tab.url });
  if (current !== epoch) return;
  if (!r.ok) return problem(r);
  const kids = [navigation(), node("h3", null, "Для этого сайта")];
  if (r.items.length === 0) kids.push(node("div", "msg", "Сохранённых паролей нет."));
  r.items.forEach(x => kids.push(item(x)));
  const sr = node("input", "sr");
  sr.placeholder = "Поиск во всех записях…";
  const box = node("div");
  let t = 0;
  let queryEpoch = 0;
  sr.addEventListener("input", () => {
    const requestEpoch = ++queryEpoch, viewEpoch = epoch;
    clearTimeout(t);
    t = setTimeout(async () => {
      box.textContent = "";
      if (sr.value.trim().length < 2) return;
      const s = await send({ type: "search", url: tab.url, query: sr.value });
      if (requestEpoch !== queryEpoch || viewEpoch !== epoch) return;
      if (!s.ok) return box.append(node("div", "msg", s.error === "rate_limited" ? "Слишком много запросов подряд — подождите минуту." : s.error));
      if (s.items.length === 0) box.append(node("div", "msg", "Ничего не найдено."));
      s.items.forEach(x => box.append(item(x)));
    }, 300);
  });
  kids.push(sr, box);
  show(...kids);
  sr.focus();
}

document.getElementById("forget").addEventListener("click", async () => {
  await send({ type: "forget" });
  pairView();
});

window.addEventListener("pagehide", () => { show(); if (watch) watch.disconnect(); });

const passkeys = document.getElementById("passkeys");
chrome.storage.local.get("passkeysEnabled").then(s => { passkeys.checked = s.passkeysEnabled !== false; });
passkeys.addEventListener("change", async () => {
  await chrome.storage.local.set({ passkeysEnabled: passkeys.checked });
  document.getElementById("passkey-note").textContent = "Перезагрузите вкладку сайта, чтобы применить настройку.";
});
start();
