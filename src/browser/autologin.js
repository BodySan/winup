// Runs only after an explicit "Войти" action in the native WinUp window.
// No credentials/codes are stored. A random expiring capability is bound by the
// native app to the paired extension, this tab, its vault generation and exact origins.
(() => {
  if(window!==window.top || window.__winupAutoLogin) return;
  window.__winupAutoLogin=true;
  const match=location.hash.match(/(?:^#|&)winup-login=([0-9a-f]{64})(?:&|$)/);
  const nonce=match?.[1];
  if(match) {
    const hash=location.hash.replace(match[0],match[0].startsWith('#')?'#':'').replace(/^#&/,'#').replace(/&$/,'');
    history.replaceState(history.state,'',location.pathname+location.search+(hash==='#'?'':hash));
  }
  const send=msg=>new Promise(resolve=>chrome.runtime.sendMessage(msg,r=>{void chrome.runtime.lastError;resolve(r||{ok:false,error:'host_error'})}));
  let job=null,stopped=false,running=false,openerUsed=false,methodUsed=false,nextUsed=false,host,root,progress,button;
  const done=new Set();
  const origin=()=>location.origin.toLowerCase();
  function displayed(e){if(!e?.isConnected)return false;const r=e.getBoundingClientRect(),s=getComputedStyle(e);return r.width>=14&&r.height>=10&&s.display!=='none'&&s.visibility!=='hidden'&&Number(s.opacity||1)>.1;}
  const visible=e=>displayed(e)&&!e.disabled&&!e.readOnly;
  const hint=e=>[e.name,e.id,e.autocomplete,e.placeholder,e.getAttribute('aria-label')].join(' ');
  const user=e=>e.tagName==='INPUT'&&['text','email','tel',''].includes(e.type)&&/user|login|email|phone|identifier|логин|почт|телефон/i.test(hint(e))&&!/otp|one-time|search|код|verification/i.test(hint(e));
  const pw=e=>e.tagName==='INPUT'&&e.type==='password'&&!/new-password/.test(e.autocomplete);
  const otp=e=>e.tagName==='INPUT'&&/one-time-code|totp|otp|2fa|mfa|verification|security.?code|код/i.test(hint(e))&&!/sms|email|почт|телефон/i.test(hint(e));
  function find(selectors,predicate){
    for(const selector of selectors||[]) {let els;try{els=Array.from(document.querySelectorAll(selector)).filter(visible).filter(predicate)}catch{return null}if(els.length===1)return els[0];if(els.length>1)return null;}
    const els=Array.from(document.querySelectorAll('input')).filter(visible).filter(predicate);return els.length===1?els[0]:null;
  }
  function control(words,scope=document,selectors,allowDisabled=false){
    for(const selector of selectors||[]){
      let controls;try{controls=Array.from(scope.querySelectorAll(selector)).filter(e=>displayed(e)&&(allowDisabled||!e.disabled&&!e.readOnly)).filter(e=>e.matches('button,a,input[type=submit],input[type=button],[role=button]'));}catch{return null;}
      if(controls.length===1)return controls[0];if(controls.length>1)return null;
    }
    const names=words||[];
    const all=Array.from(scope.querySelectorAll('button,a,input[type=submit],input[type=button],[role=button]')).filter(e=>displayed(e)&&(allowDisabled||!e.disabled&&!e.readOnly)).filter(e=>{
      const text=(e.innerText||e.value||e.getAttribute('aria-label')||'').trim().replace(/\s+/g,' ').toLowerCase();
      return names.some(w=>text===w.toLowerCase());
    });
    if(all.length===1)return all[0];
    // Desktop/mobile navigation often contains the same login link twice.
    if(all.length>1&&all.every(e=>e.tagName==='A'&&e.href===all[0].href))return all[0];
    return null;
  }
  function safeAction(e){
    if(!e)return false;
    const action=e.form?.action || (e.tagName==='A'?e.href:null);
    if(!action)return true;
    try{return job.profile.Origins.includes(new URL(action,location.href).origin.toLowerCase())}catch{return false}
  }
  function show(text){
    if(!document.documentElement)return;
    if(!host){host=document.createElement('winup-login');host.style.cssText='position:fixed;right:18px;top:18px;z-index:2147483647';root=host.attachShadow({mode:'closed'});
      const box=document.createElement('div');box.style.cssText='max-width:360px;background:#fff;color:#111;padding:12px;border:1px solid #ccd;border-radius:9px;box-shadow:0 4px 20px #0003;font:13px/1.4 Segoe UI,sans-serif';
      progress=document.createElement('div');button=document.createElement('button');button.textContent='Остановить';button.style.cssText='margin-top:8px;padding:5px 12px';button.onclick=e=>{if(e.isTrusted)end('cancelled','Автовход остановлен.');};box.append(progress,button);root.append(box);document.documentElement.append(host);}
    progress.textContent='WinUp — '+text;
  }
  async function end(stage,text){if(stopped)return;stopped=true;clearInterval(timer);show(text);if(button)button.textContent='Закрыть';if(button)button.onclick=e=>{if(e.isTrusted)host.remove()};await send({type:'login-end',stage});}
  function loginFor(e,r){if(r.login2&&(e.type==='email'||/email|e-mail|почт/i.test(hint(e)))&&!/@/.test(r.login||'')&&/@/.test(r.login2))return r.login2;
    if(r.login2&&(e.type==='tel'||/phone|телефон/i.test(hint(e)))&&!/^\+?[\d ()-]{5,}$/.test(r.login||'')&&/^\+?[\d ()-]{5,}$/.test(r.login2))return r.login2;return r.login||r.login2||'';}
  async function fill(stage,e){
    const context={url:location.href,form:e.form,action:e.form?.action,type:e.type};
    if(!safeAction(e)) {await end('unsafe_form','Адрес отправки формы изменён. Ввод остановлен.');return false;}
    const r=await send({type:'login-step',stage});
    try{
      if(!r.ok){await end(r.error,'Ввод остановлен: '+r.error);return false;}
      if(stopped || document.hidden || location.href!==context.url || !visible(e)||e.form!==context.form || e.form?.action!==context.action || e.type!==context.type || !safeAction(e)){await end('page_changed','Страница или форма изменились. Повторите вход.');return false;}
      const value=stage==='user'?loginFor(e,r):stage==='password'?r.password:r.otp;
      if(!value){await end('missing_secret','Для этого шага нет сохранённых данных.');return false;}
      if(e.value&&stage!=='password'&&e.value!==value){await end('existing_input','В поле уже есть другие данные. Проверьте их и выберите запись через значок WinUp.');return false;}
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,value);
      e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));done.add(stage);
      if(stage==='user'&&e.isConnected&&location.href===context.url&&safeAction(e))await send({type:'save-login',login:value});
      return e.isConnected && location.href===context.url && e.form===context.form && e.form?.action===context.action && safeAction(e);
    }finally{r.login=r.login2=r.password=r.otp='';}
  }
  async function tick(){
    if(!job||stopped||running||document.hidden)return;running=true;
    try{
      if(Date.now()>job.expiresAt){await end('expired','Время ожидания истекло. Повторите вход.');return;}
      if(!job.profile.Origins.includes(origin())){await end('wrong_origin','Сайт изменился. Ввод остановлен.');return;}
      if(/captcha|recaptcha|hcaptcha|challenge-platform/i.test(Array.from(document.querySelectorAll('iframe')).map(e=>e.src).join(' ')) && !find(job.profile.Password,pw)){show('пройдите проверку сайта, затем вход продолжится.');return;}
      const p=find(job.profile.Password,pw),u=find(job.profile.User,user),o=find(job.profile.Otp,otp);
      if(job.profile.Mode==='none'||job.profile.Mode==='manual'){await end('manual',job.profile.Note||'У этого ресурса другой способ входа.');return;}
      if(!p&&!methodUsed&&!done.size&&job.hasPassword){const method=control(job.profile.Method,document,job.profile.MethodSelectors);if(method&&safeAction(method)){methodUsed=true;show('выбираю вход с паролем…');method.click();return;}}
      if(u&&!done.has('user')&&(p||job.profile.Mode==='form'||control(job.profile.Next,u.form||document,job.profile.NextSelectors,true))){
        if(!await fill('user',u))return;
      }
      if(u&&done.has('user')&&!p&&!nextUsed){const next=control(job.profile.Next||['Далее','Продолжить','Next','Continue'],u.form||document,job.profile.NextSelectors);if(next&&safeAction(next)){nextUsed=true;show('логин введён, ожидаю следующий шаг…');next.click();return;}}
      if(p&&!done.has('password')&&job.hasPassword){
        const all=Array.from((p.form||document).querySelectorAll('input[type=password]')).filter(visible);
        if(all.length!==1){await end('ambiguous_form','Обнаружено несколько полей пароля. Выберите запись вручную.');return;}
        if(!await fill('password',p))return;
        const submit=control(job.profile.Submit||['Войти','Вход','Log in','Sign in','Login','Продолжить','Continue','Next','Далее'],p.form||document,job.profile.SubmitSelectors);
        show(job.autoEnter?'пароль введён, ожидаю результат…':'поля заполнены. Нажмите кнопку входа на сайте.');
        if(job.autoEnter&&submit&&safeAction(submit))submit.click();
        if(!job.hasOtp){await end('filled',job.autoEnter&&submit?'данные введены и отправлены. Проверьте результат входа.':'данные заполнены. Нажмите кнопку входа на сайте.');return;}
      }
      if(o&&job.hasOtp&&!done.has('otp')&&done.has('password')){
        if(!await fill('otp',o))return;
        const submit=control(job.profile.Submit||['Подтвердить','Продолжить','Войти','Verify','Continue','Next','Далее'],o.form||document,job.profile.SubmitSelectors);
        if(job.autoEnter&&submit&&safeAction(submit))submit.click();await end('filled','код 2FA введён. Проверьте результат входа.');return;
      }
      if(!u&&!p&&!o&&!openerUsed&&!done.size){const opener=control(job.profile.Open||['Войти','Вход','Личный кабинет','Log in','Sign in','Login'],document,job.profile.OpenSelectors);if(opener&&safeAction(opener)){openerUsed=true;show('открываю форму входа…');opener.click();return;}}
      if(done.has('password'))show('ожидаю следующий шаг. SMS, QR и подтверждение на телефоне выполните на сайте.');
      else if(!u&&!p)show('ожидаю форму входа. '+(job.profile.Note||'Если сайт просит подтверждение, выполните его.'));
      else if(!job.hasPassword&&p)show('выберите вход ключом доступа на сайте.');
    }catch{await end('failed','Не удалось определить форму. Выберите запись через значок WinUp.');}finally{running=false;}
  }
  const timer=setInterval(tick,650);
  async function claim() {
    // A fast redirect can load the next document while the native claim is still
    // being authorised. Retry briefly instead of permanently abandoning the flow.
    for(let i=0;i<4;i++) {
      const r=await send({type:'login-claim',nonce:i===0?nonce:undefined});
      if(r.ok){job=r;for(const stage of r.done||[])done.add(stage);show('ожидаю форму входа…');tick();return;}
      if(r.error!=='not_found') {clearInterval(timer);if(nonce)show('вход не запущен: '+r.error);return;}
      await new Promise(resolve=>setTimeout(resolve,350));
    }
    clearInterval(timer);if(nonce)show('вход не запущен. Повторите «Войти» в WinUp.');
  }
  claim();
})();
