// Execute the production extension scripts in a VM with a controlled DOM/Chrome API.
// These are logic regressions; they do not replace testing a real browser session.
const fs = require('fs'), vm = require('vm'), path = require('path'), assert = require('assert/strict');
const src = process.env.WINUP_TEST_BROWSER_SOURCE || path.resolve(__dirname, '../../src/browser');
let count = 0;
function check(name, condition) { assert.ok(condition, name); console.log('PASS ' + name); count++; }
function page() {
  class Node {
    constructor() { this.style = {}; this.children = []; }
    appendChild(n) { this.children.push(n); }
    append(...nodes) { this.children.push(...nodes); }
    attachShadow() { return new Node(); }
    addEventListener() {}
    remove() {}
  }
  class Input extends Node {
    constructor(type, name) { super(); this.type = type; this.name = name; this.id = name; this.tagName = 'INPUT'; this.isConnected = true; this.disabled = this.readOnly = false; this._value = ''; }
    get value() { return this._value; }
    set value(v) { this._value = v; }
    getBoundingClientRect() { return { width: 160, height: 24, left: 10, right: 170, top: 10, bottom: 34 }; }
    getAttribute(n) { return n === 'type' ? this.type : n === 'autocomplete' ? (this.name === 'otp' ? 'one-time-code' : this.name === 'username' ? 'username' : '') : ''; }
    closest() { return this.form; }
    dispatchEvent(e) { if (this.onDispatch) this.onDispatch(e); }
    focus() {}
  }
  const user = new Input('text', 'username'), pw = new Input('password', 'password'), otp = new Input('text', 'otp');
  const form = { action: 'https://example.com/session', fields: [user, pw, otp], querySelectorAll(q) { return this.fields.filter(e => q !== 'input[type=password]' || e.type === 'password'); } };
  [user, pw, otp].forEach(e => e.form = form);
  const doc = { documentElement: new Node(), body: new Node(), activeElement: pw, createElement: () => new Node(), querySelectorAll: q => form.querySelectorAll(q), addEventListener() {} };
  let listener, callback;
  const window = {}; window.top = window;
  const sandbox = { window, document: doc, location: { href: 'https://example.com/login', origin: 'https://example.com' },
    chrome: { runtime: { id: 'our-extension', getURL: x => x, sendMessage: (m, cb) => callback = cb, onMessage: { addListener: fn => listener = fn } } },
    HTMLInputElement: Input, HTMLTextAreaElement: Input, Event: class { constructor(type) { this.type = type; } },
    getComputedStyle: e => ({ display: e.hidden ? 'none' : 'block', visibility: 'visible', opacity: '1', filter: 'none', clipPath: 'none' }),
    IntersectionObserver: class { observe() {} disconnect() {} }, MutationObserver: class { observe() {} },
    addEventListener() {}, setInterval() {}, setTimeout() {}, clearTimeout() {}, scrollX: 0, scrollY: 0, console };
  let code = fs.readFileSync(path.join(src, 'content.js'), 'utf8');
  code = code.replace(/\}\)\(\);\s*$/, 'globalThis.audit = { fillContext, contextValid, apply };\n})();');
  vm.runInNewContext(code, sandbox, { filename: 'content.js' });
  return { ...sandbox, user, pw, otp, form, audit: sandbox.audit, listener: (...a) => listener(...a), respond: r => callback(r) };
}
const credentials = () => ({ ok: true, password: 'SYNTHETIC-PASSWORD', login: 'SYNTHETIC-USER', otp: '123456' });
function changes(name, change, field = 'pw') {
  const p = page(), c = p.audit.fillContext(p[field]); change(p);
  check(name, !p.audit.contextValid(c) && !p.audit.apply(credentials(), c) && p.pw.value === '');
}
async function main() {
  const stable = page(), c = stable.audit.fillContext(stable.pw);
  check('stable-form-fills', stable.audit.apply(credentials(), c) && stable.pw.value === 'SYNTHETIC-PASSWORD' && stable.otp.value === '123456');
  changes('navigation-cancels-fill', p => p.location.href = 'https://example.com/other');
  changes('form-action-change-cancels-fill', p => p.form.action = 'https://attacker.example/');
  changes('detached-password-cancels-fill', p => p.pw.isConnected = false);
  changes('hidden-password-cancels-fill', p => p.pw.hidden = true);
  changes('password-type-change-cancels-fill', p => p.pw.type = 'text');
  changes('username-request-cannot-switch-password', p => { p.pw.isConnected = false; p.form.fields = [p.user, new p.HTMLInputElement('password', 'replacement')]; p.form.fields[1].form = p.form; }, 'user');
  changes('otp-replacement-cancels-fill', p => p.otp.isConnected = false);
  const sync = page(), sc = sync.audit.fillContext(sync.pw);
  sync.user.onDispatch = () => sync.location.href = 'https://example.com/changed-by-input';
  check('synchronous-input-navigation-stops-password', !sync.audit.apply(credentials(), sc) && sync.pw.value === '' && sync.otp.value === '');
  const popup = page(); let outcome;
  popup.listener({ type: 'fillFromPopup', id: 'test' }, { id: 'our-extension' }, r => outcome = r);
  popup.location.href = 'https://example.com/new'; const result = credentials(); popup.respond(result); await Promise.resolve(); await Promise.resolve();
  check('pending-popup-navigation-cancels-fill', outcome && outcome.error === 'page_changed' && popup.pw.value === '' && result.password === '');
  const good = page(); outcome = null;
  good.listener({ type: 'fillFromPopup', id: 'test' }, { id: 'our-extension' }, r => outcome = r);
  good.respond(credentials()); await Promise.resolve(); await Promise.resolve();
  check('popup-response-does-not-forward-secrets', outcome.ok && !('password' in outcome) && !('login' in outcome) && !('otp' in outcome));
  let foreign = false;
  good.listener({ type: 'fillFromPopup', id: 'test' }, { id: 'other-extension' }, () => foreign = true);
  check('foreign-popup-message-rejected', !foreign);

  let listener, nativeRequest;
  let passkeysEnabled=false;
  const bg = { console, navigator: { userAgent: 'Chrome' }, chrome: { runtime: { id: 'our-extension', getURL:p=>'chrome-extension://our-extension/'+p,
    sendNativeMessage: (host, msg, cb) => { nativeRequest = msg; cb({ ok: true }); }, onMessage: { addListener: fn => listener = fn } },
    storage: { local: { get: async () => ({ token: 'synthetic-token',passkeysEnabled }) } } } };
  vm.runInNewContext(fs.readFileSync(path.join(src, 'background.js'), 'utf8'), bg, { filename: 'background.js' });
  await new Promise(resolve => listener({ type: 'fill', id: 'test', url: 'https://spoofed.example', framed: false }, { id: 'our-extension', tab: {}, url: 'https://actual.example/login', frameId: 4 }, resolve));
  check('background-uses-browser-url-and-frame', nativeRequest.url === 'https://actual.example/login' && nativeRequest.framed === true);
  let rejected;
  listener({ type: 'fill' }, { id: 'other-extension' }, r => rejected = r);
  check('foreign-background-message-rejected', rejected && rejected.error === 'bad_request');
  listener({ type: 'fill' }, { id: 'our-extension', tab: {}, frameId: 0 }, r => rejected = r);
  check('missing-browser-url-rejected', rejected.error === 'bad_request');
  for(const type of ['otp','otp-list','otp-copy']) {
    listener({type,id:'otp'}, {id:'our-extension',tab:{},url:'https://actual.example',frameId:0},r=>rejected=r);
    check(type+'-denied-to-content',rejected.error==='bad_request');
  }
  listener({type:'otp'}, {id:'our-extension',url:'chrome-extension://our-extension/other.html'},r=>rejected=r);
  check('otp-denied-to-other-extension-page',rejected.error==='bad_request');
  await new Promise(resolve=>listener({type:'otp-copy',id:'otp',generation:7},{id:'our-extension',url:'chrome-extension://our-extension/popup.html'},resolve));
  check('otp-copy-only-through-native-host',nativeRequest.type==='otp-copy' && nativeRequest.generation===7 && !('otp' in nativeRequest));
  listener({type:'otp-fill'},{id:'our-extension',tab:{},url:'https://actual.example',frameId:4},r=>rejected=r);
  check('otp-fill-frame-rejected',rejected.error==='bad_request');
  listener({type:'passkey-create'},{id:'our-extension',tab:{},url:'https://actual.example',frameId:4},r=>rejected=r);
  check('passkey-frame-rejected',rejected.error==='SecurityError');
  const passkeyResult=await new Promise(resolve=>listener({type:'passkey-create',requestId:'test'}, {id:'our-extension',tab:{},url:'https://actual.example',frameId:0},resolve));
  check('passkey-opt-in-disabled-falls-back',passkeyResult.fallback===true);
  passkeysEnabled=true;
  await new Promise(resolve=>listener({type:'passkey-create',requestId:'test',url:'https://spoofed.example'},{id:'our-extension',tab:{},url:'https://actual.example',frameId:0},resolve));
  check('passkey-uses-browser-owned-origin',nativeRequest.type==='passkey-create' && nativeRequest.url==='https://actual.example' && nativeRequest.framed===false);
  console.log('TOTAL passes=' + count);
}
main().catch(e => { console.error(e); process.exitCode = 1; });
