(() => {
  'use strict';
  const kinds=new Set(['cc-number','cc-name','cc-given-name','cc-family-name','cc-exp','cc-exp-month','cc-exp-year','cc-csc','cc-type']);
  let pending=null;
  function kind(el){
    const tokens=(el.getAttribute('autocomplete')||'').toLowerCase().split(/\s+/);
    for(const token of tokens)if(kinds.has(token))return token;
    const label=[el.name,el.id,el.getAttribute('aria-label'),el.placeholder,...[...(el.labels||[])].map(l=>l.textContent.slice(0,120))].join(' ').toLowerCase().slice(0,800);
    if(/(?:card[\s_-]*(?:number|no)|cc[\s_-]*number|номер[\s_-]*карты|\bpan\b)/i.test(label))return 'cc-number';
    if(/\b(?:cvv2?|cvc2?|csc)\b/.test(label))return 'cc-csc';
    if(/card[\s_-]*(?:holder|owner|name)|держател[ья]/.test(label))return 'cc-name';
    if(/expir|exp[\s_-]|срок.*действ/.test(label))return /month|месяц/.test(label)?'cc-exp-month':/year|год/.test(label)?'cc-exp-year':'cc-exp';
    return null;
  }
  function visible(el){
    if(!el.isConnected||el.disabled||el.readOnly||el.type==='hidden'||el.type==='submit'||el.getClientRects().length===0)return false;
    for(let p=el;p&&p.nodeType===1;p=p.parentElement){const style=getComputedStyle(p);if(style.display==='none'||style.visibility!=='visible'||Number(style.opacity)===0)return false;}
    return true;
  }
  function https(value){try{const u=new URL(value);return u.protocol==='https:'&&!u.username&&!u.password?u:null;}catch{return null;}}
  function collect(){
    if(!https(location.href))return {ok:false,error:'insecure'};
    const groups=new Map();
    for(const el of document.querySelectorAll('input,select')){
      const type=kind(el);if(!type||!visible(el))continue;
      const group=el.form||document; if(!groups.has(group))groups.set(group,[]);groups.get(group).push({el,type});
    }
    const values=[...groups.values()];const focused=values.find(g=>g.some(f=>f.el===document.activeElement));
    const numbered=values.filter(g=>g.some(f=>f.type==='cc-number'));
    const selected=focused||(numbered.length===1?numbered[0]:values.length===1?values[0]:null);
    if(!selected)return {ok:false,error:values.length?'ambiguous_form':'no_card_fields'};
    const types=selected.map(f=>f.type);if(new Set(types).size!==types.length)return {ok:false,error:'ambiguous_form'};
    const form=selected[0].el.form;
    const action=form?https(form.action):https(location.href);if(!action)return {ok:false,error:'insecure_form'};
    const nonce=crypto.randomUUID();pending={nonce,url:location.href,fields:selected,expires:Date.now()+90000,form,action:form?.action||''};
    return {ok:true,nonce,fields:types,actionOrigin:action.origin};
  }
  const months=['january','february','march','april','may','june','july','august','september','october','november','december'];
  const ruMonths=['январ','феврал','март','апрел','ма','июн','июл','август','сентябр','октябр','ноябр','декабр'];
  function valueFor(field,card){
    const {el,type}=field,m=String(card.month).padStart(2,'0'),y=String(card.year);
    const parts=card.holder.trim().split(/\s+/);
    let value=type==='cc-number'?card.number:type==='cc-csc'?card.cvv:type==='cc-name'?card.holder:type==='cc-given-name'?parts[0]:type==='cc-family-name'?parts.slice(1).join(' '):type==='cc-exp-month'?m:type==='cc-exp-year'?y:type==='cc-type'?card.brand:el.type==='month'?`${y}-${m}`:/yyyy|гггг/i.test(el.placeholder)||el.maxLength>=7&&el.maxLength<=10?`${m}/${y}`:`${m}/${y.slice(-2)}`;
    if(el.tagName==='SELECT'){
      const option=[...el.options].find(o=>{
        if(o.disabled||o.value==='')return false;
        if(type==='cc-exp-month'){
          const choices=[...el.options].filter(x=>!x.disabled&&x.value!=='');
          const named=choices.find(x=>x.text.toLowerCase().includes(months[card.month-1])||x.text.toLowerCase().startsWith(ruMonths[card.month-1]));
          if(named)return o===named;
          const zero=choices.some(x=>x.value==='0')&&!choices.some(x=>Number(x.value)===12)&&choices.length===12;
          return Number(o.value)===card.month-(zero?1:0);
        }
        if(type==='cc-exp-year')return Number(o.value)===card.year||Number(o.value)===card.year%100;
        const normalize=s=>String(s).toLowerCase().replace(/[\s_-]/g,'').replace('мир','mir').replace('americanexpress','amex');
        return normalize(o.value)===normalize(value)||normalize(o.text)===normalize(value);
      });if(!option)throw Error('unsupported_options');value=option.value;
    }else if(type==='cc-exp-year'&&el.maxLength===2)value=y.slice(-2);
    return value;
  }
  function fill(msg){
    const plan=pending;pending=null;
    if(!plan||msg.nonce!==plan.nonce||Date.now()>plan.expires||location.href!==plan.url||msg.url!==location.href)return {ok:false,error:'page_changed'};
    if(plan.form&&plan.form.action!==plan.action)return {ok:false,error:'page_changed'};
    if(plan.fields.some(f=>!visible(f.el)||kind(f.el)!==f.type||f.el.form!==plan.form))return {ok:false,error:'form_changed'};
    const values=plan.fields.map(f=>({field:f,value:valueFor(f,msg.card)})).filter(x=>x.value!=null);
    for(const {field,value}of values){
      const prototype=field.el.tagName==='SELECT'?HTMLSelectElement.prototype:HTMLInputElement.prototype;
      Object.getOwnPropertyDescriptor(prototype,'value').set.call(field.el,String(value));
      field.el.dispatchEvent(new Event('input',{bubbles:true}));field.el.dispatchEvent(new Event('change',{bubbles:true}));
    }
    return {ok:true,filled:values.length};
  }
  chrome.runtime.onMessage.addListener((msg,sender,reply)=>{
    if(sender.id!==chrome.runtime.id||!msg||!['cards-probe','cards-fill'].includes(msg.type))return;
    try{reply(msg.type==='cards-probe'?collect():fill(msg));}catch{reply({ok:false,error:'unsupported_form'});}
  });
})();
