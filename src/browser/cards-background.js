// These functions run only in the extension background, never in a site's world.
function cardHttps(value){try{const u=new URL(value);return u.protocol==='https:'&&!u.username&&!u.password?u:null;}catch{return null;}}
function cardPermissions(){return /Firefox\//.test(navigator.userAgent)?{permissions:['webNavigation'],data_collection:['financialAndPaymentInfo','personallyIdentifyingInfo']}:{permissions:['webNavigation']};}
async function cardInsert(msg){
  if(!Number.isInteger(msg.tabId)||typeof msg.id!=='string')return {ok:false,error:'bad_request'};
  const tab=await chrome.tabs.get(msg.tabId);
  if(!tab.active||!cardHttps(tab.url))return {ok:false,error:'insecure'};
  const frames=await chrome.webNavigation.getAllFrames({tabId:tab.id});const targets=[];
  for(const frame of frames||[]){
    if(!cardHttps(frame.url)||targets.length>=8)continue;
    try{const plan=await chrome.tabs.sendMessage(tab.id,{type:'cards-probe'},{frameId:frame.frameId});
      if(plan?.ok&&typeof plan.nonce==='string'&&Array.isArray(plan.fields)&&plan.fields.length<=9&&cardHttps(plan.actionOrigin))targets.push({frame,plan});
    }catch{/* A restricted or unloaded frame receives no card data. */}
  }
  if(!targets.some(t=>t.plan.fields.includes('cc-number')))return {ok:false,error:'no_card_fields'};
  const origins=[...new Set(targets.flatMap(t=>[cardHttps(t.frame.url).origin,t.plan.actionOrigin]))];
  const t=await token();let card=null;
  try{
    card=await native({type:'card-fill',token:t,id:msg.id,url:tab.url,origins});if(!card?.ok)return card||{ok:false,error:'host_error'};
    const current=await chrome.tabs.get(tab.id);if(!current.active||current.url!==tab.url)return {ok:false,error:'page_changed'};
    const now=await chrome.webNavigation.getAllFrames({tabId:tab.id});
    for(const target of targets){const frame=now.find(f=>f.frameId===target.frame.frameId);if(!frame||frame.url!==target.frame.url||frame.documentId!==target.frame.documentId)return {ok:false,error:'page_changed'};}
    const status=await native({type:'status',token:t});if(!status?.ok||status.state!=='open'||status.generation!==card.generation)return {ok:false,error:'locked'};
    let filled=0;
    for(const target of targets){
      const fields=new Set(target.plan.fields),part={month:card.month,year:card.year,holder:fields.has('cc-name')||fields.has('cc-given-name')||fields.has('cc-family-name')?card.holder:'',number:fields.has('cc-number')?card.number:'',cvv:fields.has('cc-csc')?card.cvv:'',brand:fields.has('cc-type')?card.brand:''};
      try{const result=await chrome.tabs.sendMessage(tab.id,{type:'cards-fill',nonce:target.plan.nonce,url:target.frame.url,card:part},{frameId:target.frame.frameId});if(!result?.ok)return {ok:false,error:result?.error||'form_changed',filled};filled+=result.filled||0;}
      finally{part.number=part.cvv=part.holder='';}
    }
    return {ok:true,filled};
  }finally{if(card){card.number=card.cvv=card.holder='';card=null;}}
}
