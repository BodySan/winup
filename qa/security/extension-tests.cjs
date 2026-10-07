// Execute the production extension scripts in a VM with a controlled DOM/Chrome API.
// These are logic regressions; they do not replace testing a real browser session.
const fs = require('fs'), vm = require('vm'), path = require('path'), assert = require('assert/strict');
const src = process.env.WINUP_TEST_BROWSER_SOURCE || path.resolve(__dirname, '../../src/browser');
let count = 0;
function check(name, condition) { assert.ok(condition, name); console.log('PASS ' + name); count++; }
function page() {
  class Node {
    constructor() { this.style = {}; this.children = []; this._text=''; }
    get textContent() { return this._text; }
    set textContent(value) { this._text=value; this.children=[]; }
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
  let listener, callback; const requests=[];
  const window = {}; window.top = window;
  const sandbox = { window, document: doc, location: { href: 'https://example.com/login', origin: 'https://example.com' },
    chrome: { runtime: { id: 'our-extension', getURL: x => x, sendMessage: (m, cb) => { callback = cb; requests.push({message:m,reply:cb}); }, onMessage: { addListener: fn => listener = fn } } },
    HTMLInputElement: Input, HTMLTextAreaElement: Input, Event: class { constructor(type) { this.type = type; } },
    getComputedStyle: e => ({ display: e.hidden ? 'none' : 'block', visibility: 'visible', opacity: '1', filter: 'none', clipPath: 'none' }),
    IntersectionObserver: class { observe() {} disconnect() {} }, MutationObserver: class { observe() {} },
    addEventListener() {}, setInterval() {}, setTimeout() {}, clearTimeout() {}, scrollX: 0, scrollY: 0, console };
  let code = fs.readFileSync(path.join(src, 'content.js'), 'utf8');
  code = code.replace(/\}\)\(\);\s*$/, 'globalThis.audit = { fillContext, contextValid, apply, saveCandidate, loginFor, toggle, search, dropdownState:()=>({dd,ddFor}) };\n})();');
  vm.runInNewContext(code, sandbox, { filename: 'content.js' });
  return { ...sandbox, user, pw, otp, form, requests, audit: sandbox.audit, listener: (...a) => listener(...a), respond: r => callback(r) };
}
const credentials = () => ({ ok: true, password: 'SYNTHETIC-PASSWORD', login: 'SYNTHETIC-USER', otp: '123456' });
function changes(name, change, field = 'pw') {
  const p = page(), c = p.audit.fillContext(p[field]); change(p);
  check(name, !p.audit.contextValid(c) && !p.audit.apply(credentials(), c) && p.pw.value === '');
}
async function passkeyPageTests() {
  const listeners=new Map(), requests=[]; let focused=true, reply={error:'TypeError'};
  const native={create:async()=>({native:true}),get:async()=>({native:true}),store:async()=>{},preventSilentAccess:async()=>{}};
  const document={hasFocus:()=>focused,addEventListener(type,fn){if(!listeners.has(type))listeners.set(type,new Set());listeners.get(type).add(fn);},
    removeEventListener(type,fn){listeners.get(type)?.delete(fn);},dispatchEvent(e){
      if(e.type==='winup-passkeys-request') { const request=JSON.parse(e.detail); requests.push(request);
        if(request.action==='abort') return;
        const result=request.action==='available'?{enabled:true}:reply;
        for(const fn of [...listeners.get('winup-passkeys-response')||[]])fn({detail:JSON.stringify({...result,requestId:request.requestId})});
      } else for(const fn of [...listeners.get(e.type)||[]])fn(e);
    }};
  const context={console,document,navigator:{credentials:native},crypto:require('crypto').webcrypto,ArrayBuffer,Uint8Array,TypeError,DOMException,
    window:{atob:s=>Buffer.from(s,'base64').toString('binary'),btoa:s=>Buffer.from(s,'binary').toString('base64')},
    CustomEvent:class{constructor(type,options){this.type=type;this.detail=options.detail;}},
    PublicKeyCredential:class{},AuthenticatorAttestationResponse:class{},AuthenticatorAssertionResponse:class{},setTimeout,clearTimeout};
  vm.runInNewContext(fs.readFileSync(path.join(src,'passkeys.js'),'utf8'),context,{filename:'passkeys.js'});
  for(let n=0;n<30 && context.navigator.credentials===native;n++)await new Promise(r=>setTimeout(r,10));
  check('passkey-main-provider-installed',context.navigator.credentials!==native);
  let error;
  try{await context.navigator.credentials.create({publicKey:{challenge:new Uint8Array(32)}});}catch(e){error=e;}
  check('passkey-type-error-preserved',error?.name==='TypeError');
  const controller=new AbortController();controller.abort(); const before=requests.length;
  try{await context.navigator.credentials.get({publicKey:{challenge:new Uint8Array(32)},signal:controller.signal});}catch(e){error=e;}
  check('passkey-already-aborted-does-not-request-signature',error?.name==='AbortError' && requests.slice(before).every(r=>r.action==='abort'));
  const cyclic={challenge:new Uint8Array(32)};cyclic.extensions=cyclic;
  try{await context.navigator.credentials.create({publicKey:cyclic});}catch(e){error=e;}
  check('passkey-cyclic-request-has-no-pending-listener',error?.name==='TypeError' && listeners.get('winup-passkeys-response').size===0);
  try{await context.navigator.credentials.create({publicKey:{challenge:new Uint8Array(32),extensions:{large:'x'.repeat(61000)}}});}catch(e){error=e;}
  check('passkey-oversized-request-fails-without-native-call',error?.name==='TypeError' && listeners.get('winup-passkeys-response').size===0);
  focused=false; reply={fallback:true};const abort=new AbortController();
  const pending=context.navigator.credentials.get({publicKey:{challenge:new Uint8Array(32)},signal:abort.signal}).catch(e=>e);
  await Promise.resolve(); await Promise.resolve();abort.abort();const cancelled=await pending;
  check('passkey-fallback-focus-wait-respects-cancellation',cancelled.name==='AbortError' && listeners.get('focus').size===0);
}
async function popupTests() {
  class Node {
    constructor(){this.children=[];this.handlers=new Map();this._text='';}
    get textContent(){return this._text;} set textContent(value){this._text=value;this.children=[];}
    append(...nodes){this.children.push(...nodes);} focus(){}
    addEventListener(type,fn){this.handlers.set(type,fn);}
  }
  const elements=new Map(),requests=[];let interval;
  const document={createElement:()=>new Node(),getElementById:id=>{if(!elements.has(id))elements.set(id,new Node());return elements.get(id);}};
  const context={console,document,performance:{now:()=>0},window:{addEventListener(){},close(){}},
    setInterval:fn=>{interval=fn;return 1;},clearInterval:()=>{interval=null;},setTimeout,clearTimeout,
    chrome:{tabs:{query:async()=>[{id:1,url:'https://example.com'}]},storage:{local:{get:async()=>({passkeysEnabled:true})}},
      runtime:{sendMessage(msg,reply){requests.push(msg);if(msg.type==='otp')reply({ok:true,otp:'123456',id:'synthetic-otp',name:'SYNTHETIC',generation:1,serverTime:Date.now(),expiresAt:Date.now()+30000});}}}};
  vm.createContext(context);vm.runInContext(fs.readFileSync(path.join(src,'popup.js'),'utf8'),context,{filename:'popup.js'});
  vm.runInContext('watchReady=true;generation=1;lastWatch=Date.now()',context);
  await context.otpView('synthetic-otp');
  const display=elements.get('main').children[2],copy=elements.get('main').children[4],insert=elements.get('main').children[5];
  check('popup-live-code-rendered',display.textContent==='123456');
  context.problem({error:'locked'});
  check('popup-lock-clears-detached-code-and-controls',display.textContent==='' && copy.disabled && insert.disabled && interval===null);
  vm.runInContext('watchReady=true',context);const before=requests.length;await copy.handlers.get('click')();
  check('popup-detached-copy-cannot-reuse-erased-code',requests.length===before);
}
async function main() {
  const stable = page(), c = stable.audit.fillContext(stable.pw);
  check('stable-form-fills', stable.audit.apply(credentials(), c) && stable.pw.value === 'SYNTHETIC-PASSWORD' && stable.otp.value === '123456');
  const secondary=page(); secondary.user.type='email'; secondary.audit.apply({...credentials(),login:'nickname',login2:'synthetic@example.com'},secondary.audit.fillContext(secondary.pw));
  check('email-field-selects-secondary-login',secondary.user.value==='synthetic@example.com');
  const phone=page(); phone.user.type='tel'; phone.audit.apply({...credentials(),login:'nickname',login2:'+7 900 000 00 00'},phone.audit.fillContext(phone.pw));
  check('phone-field-selects-secondary-login',phone.user.value==='+7 900 000 00 00');
  const save=page(); save.user.value='synthetic';save.pw.value='Synthetic-Pass!';
  check('save-candidate-uses-live-fields',save.audit.saveCandidate(save.pw).pw===save.pw);
  save.window.top={};check('save-child-frame-rejected',save.audit.saveCandidate(save.pw)===null);save.window.top=save.window;
  save.form.fields.push(new save.HTMLInputElement('password','confirmation'));
  check('save-ambiguous-password-fields-rejected',save.audit.saveCandidate(save.pw)===null);
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

  const dropdown=page(); dropdown.audit.toggle(dropdown.pw); dropdown.audit.toggle(dropdown.otp);
  dropdown.requests[0].reply({ok:true,items:[{id:'old',name:'OLD PASSWORD',login:'old'}]}); await Promise.resolve();
  check('stale-list-does-not-replace-new-dropdown',dropdown.audit.dropdownState().dd.children[1].textContent==='Загрузка…');
  dropdown.requests[1].reply({ok:true,items:[{id:'new',name:'LIVE OTP',login:'new',otp:true}]}); await Promise.resolve();
  check('new-dropdown-keeps-its-own-response',dropdown.audit.dropdownState().dd.children[1].children[0].textContent==='LIVE OTP');
  const search=page(); search.audit.toggle(search.pw); search.respond({ok:true,items:[]}); await Promise.resolve();
  const box=search.document.createElement('div');
  const first=search.audit.search('first',box), second=search.audit.search('second',box);
  search.requests[2].reply({ok:true,items:[{id:'second',name:'SECOND',login:'second'}]}); await second;
  search.requests[1].reply({ok:true,items:[{id:'first',name:'FIRST',login:'first'}]}); await first;
  check('out-of-order-search-response-ignored',box.children.length===1 && box.children[0].children[0].textContent==='SECOND');
  const pendingSearch=search.audit.search('pending',box); await search.audit.search('',box);
  search.requests[3].reply({ok:true,items:[{id:'pending',name:'PENDING',login:'pending'}]}); await pendingSearch;
  check('cleared-search-does-not-restore-old-results',box.children.length===0);

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
  await passkeyPageTests();
  await popupTests();
  console.log('TOTAL passes=' + count);
}
main().catch(e => { console.error(e); process.exitCode = 1; });
