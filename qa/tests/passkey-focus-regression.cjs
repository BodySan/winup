// Ordinary UI regression: return from the WinUp consent window to native WebAuthn.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(require('node:path').join(__dirname,'../../src/browser/passkeys.js'),'utf8');
const start=source.indexOf('const waitForFocus ='),end=source.indexOf('\n    /**',start);
assert(start>=0&&end>start);
function fixture(){let focused=false;const document=new EventTarget(),window=new EventTarget();document.hasFocus=()=>focused;const context=vm.createContext({document,window,DOMException});vm.runInContext(source.slice(start,end)+'\nthis.waitForFocus=waitForFocus;',context);return {document,window,wait:context.waitForFocus,focus:()=>{focused=true;}};}
(async()=>{
 let f=fixture(),resolved=false;let pending=f.wait().then(()=>resolved=true);
 await Promise.resolve();assert.equal(resolved,false);f.focus();f.window.dispatchEvent(new Event('focus'));await pending;assert.equal(resolved,true);
 console.log('PASS native-provider-resumes-on-window-focus');
 f=fixture();const controller=new AbortController();pending=f.wait(controller.signal);controller.abort();await assert.rejects(pending,e=>e.name==='AbortError');f.focus();f.window.dispatchEvent(new Event('focus'));
 console.log('PASS native-provider-focus-wait-can-be-cancelled');
 f=fixture();pending=f.wait();f.focus();f.document.dispatchEvent(new Event('visibilitychange'));await pending;
 console.log('PASS native-provider-resumes-after-visibility-change');
})().catch(e=>{console.error(e);process.exitCode=1;});
