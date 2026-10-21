(() => {
  window.cardFormResults=[];
  let listener;
  chrome.runtime={id:'winup-card-qa',onMessage:{addListener:fn=>listener=fn}};
  window.cardQaInitialize=source=>{(0,eval)(source);};
  window.cardQaRun=()=>{
    const results=window.cardFormResults;
    const check=(name,ok)=>{results.push({name,passed:!!ok});if(!ok)throw Error(name);};
    const root=document.createElement('section');root.id='card-form-qa';root.style.cssText='position:fixed;inset:40px;background:white;color:black;z-index:9000;padding:20px;overflow:auto';document.body.append(root);
    const sample={number:'4111111111111111',cvv:'923',holder:'TEST OWNER',month:12,year:2098,brand:'Visa'};
    const call=msg=>{let result;listener(msg,{id:'winup-card-qa'},r=>result=r);return result;};
    const probe=()=>call({type:'cards-probe'});
    const fill=(plan,extra={})=>call({type:'cards-fill',nonce:plan.nonce,url:location.href,card:sample,...extra});
    const base=()=>root.innerHTML='<form id="card-form"><label>Номер карты<input autocomplete="cc-number" id="test-pan"></label><input autocomplete="cc-name" id="test-holder"><input autocomplete="cc-exp" placeholder="MM/YY" id="test-exp"><input autocomplete="cc-csc" id="test-cvv"><input autocomplete="cc-number" id="honeypot" style="display:none"><button type="submit">Оплатить</button></form>';
    try{
      base();let submits=0;root.querySelector('form').onsubmit=e=>{e.preventDefault();submits++;};let plan=probe();check('Visible payment fields recognized; hidden PAN ignored',plan.ok&&plan.fields.length===4);
      let reply=fill(plan);check('Number, holder, expiry and CVV fill actual DOM',reply.ok&&document.getElementById('test-pan').value===sample.number&&document.getElementById('test-holder').value==='TEST OWNER'&&document.getElementById('test-exp').value==='12/98'&&document.getElementById('test-cvv').value==='923');
      check('Hidden field unchanged and payment never submitted',document.getElementById('honeypot').value===''&&submits===0);
      check('One-use form nonce cannot be replayed',!fill(plan).ok);
      base();plan=probe();check('Changed destination URL cancels filling',fill(plan,{url:location.href+'#other'}).error==='page_changed'&&document.getElementById('test-pan').value==='');
      base();plan=probe();document.getElementById('test-pan').outerHTML='<input id="test-pan" autocomplete="cc-number">';check('Replacing input after approval cancels filling',fill(plan).error==='form_changed'&&document.getElementById('test-pan').value==='');
      base();plan=probe();document.getElementById('test-pan').style.display='none';check('Hiding input after approval cancels filling',fill(plan).error==='form_changed');
      base();plan=probe();document.getElementById('card-form').action='https://other.example/pay';check('Changing form action cancels filling',fill(plan).error==='page_changed');
      base();root.querySelector('form').action='http://insecure.example/pay';check('Insecure form action is blocked',probe().error==='insecure_form');
      root.innerHTML='<form><input autocomplete="cc-number"></form><form><input autocomplete="cc-number"></form>';document.activeElement.blur();check('Ambiguous payment forms require focus',probe().error==='ambiguous_form');root.querySelector('input').focus();plan=probe();check('Focused payment form is selected explicitly',plan.ok&&fill(plan).ok&&root.querySelectorAll('input')[1].value==='');
      root.innerHTML='<form><input autocomplete="cc-number"><select autocomplete="cc-exp-month" id="months">'+Array.from({length:12},(_,i)=>`<option value="${i}">${i+1}</option>`).join('')+'</select><select autocomplete="cc-exp-year" id="years"><option value="98">2098</option></select></form>';
      plan=probe();check('Zero-based month and two-digit year selects work',fill(plan).ok&&document.getElementById('months').value==='11'&&document.getElementById('years').value==='98');
      root.innerHTML='<form><input autocomplete="cc-number"><input autocomplete="cc-exp" type="month" id="exp-month"><input autocomplete="cc-csc" id="old-cvv" value="555"></form>';plan=probe();reply=fill(plan,{card:{...sample,cvv:''}});check('Month input uses YYYY-MM and absent CVV clears stale value',reply.ok&&document.getElementById('exp-month').value==='2098-12'&&document.getElementById('old-cvv').value==='');
      root.innerHTML='<form><input name="cardNumber" id="legacy-pan"><input name="cvv" id="legacy-cvv"><input name="expiryMonth" id="legacy-month"><input name="expiryYear" maxlength="2" id="legacy-year"></form>';plan=probe();check('Conservative legacy field names and two-digit year work',plan.ok&&fill(plan).ok&&document.getElementById('legacy-pan').value===sample.number&&document.getElementById('legacy-year').value==='98');
      check('Card data not written to web storage',!JSON.stringify([Object.entries(localStorage),Object.entries(sessionStorage)]).includes(sample.number));
    }finally{root.remove();}
    return results;
  };
})();
