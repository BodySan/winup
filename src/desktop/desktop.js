'use strict';
const desktop={actions:[],ready:false,pending:new Set(),requests:new Map(),seq:0,structure:'',snapshot:null,secretTimer:null,secret:null,menuSelection:null,commandScope:null,commandStructure:''};
const sectionNames={passwords:'Пароли',otp:'2FA',passkeys:'Ключи доступа',files:'Файлы',run:'Запуск',winget:'WinGet',install:'Установка',download:'Скачать'};
desktop.selection={};desktop.checked={};
for(const key of Object.keys(A))delete A[key];
for(const key of ['accounts','otps','passkeys','apps','packages','installers','files','vaults','trash','components'])state[key]=[];
state.links=[];state.groups=[];state.checked.clear();state.fileSelection.clear();state.vaultLocked=true;state.database='vault.kdbx';state.queue=null;state.activity=[];state.browser='';state.silent=true;
const normal=text=>String(text).replace(/[.…]/g,'').replace(/\s+/g,' ').trim();
const prettyCode=code=>{code=String(code||'');const half=code.length===8?4:3;return code.length===6||code.length===8?code.slice(0,half)+' '+code.slice(half):code;};
const nativeActions=(section=sectionNames[state.section])=>desktop.actions.filter(a=>a.section===section);
function entryCategories(){return [...new Set(state.accounts.map(a=>a.category).filter(Boolean))].sort((a,b)=>a.localeCompare(b,'ru'));}
function payloadForSection(section,extra={}){return {section:sectionNames[section]||section,selected:state.selected||'',otp:desktop.selection.otp||'',key:desktop.selection.passkeys||'',app:desktop.selection[section==='install'?'install':'run']||'',link:desktop.selection.download||'',checked:[...(section===state.section?state.checked:desktop.checked[section]||[])],files:[...state.fileSelection],silent:state.silent,...extra};}
function payload(extra={}){return payloadForSection(state.section,extra);}
navigate=function(section){if(!sections[section])return;if(section!==state.section){desktop.checked[state.section]=new Set(state.checked);state.section=section;state.query='';state.checked=new Set(desktop.checked[section]||[]);closeMenu();location.hash=section;render();window.scrollTo({top:0,behavior:'instant'});}else render();};
const sectionKey=section=>Object.keys(sectionNames).find(k=>sectionNames[k]===section)||section;
const operationBusy=()=>state.running||[...desktop.requests.values()].some(request=>request.command!=='refresh');
function host(command,extra={}){
  if(!window.chrome?.webview){toast('Эта страница открывается внутри WinUp.',true);return false;}
  if(command==='refresh'&&[...desktop.requests.values()].some(request=>request.command==='refresh'))return false;
  const cancel=command==='native'&&desktop.actions.find(a=>a.id===extra.actionId)?.title.startsWith('Отмен');
  if(command!=='refresh'&&operationBusy()&&!['lock-secrets','lock-all'].includes(command)&&!cancel){toast('Дождитесь завершения операции или отмените её.',true);return false;}
  const requestId=String(++desktop.seq);desktop.pending.add(requestId);desktop.requests.set(requestId,{command,section:extra.section||sectionNames[state.section]});
  try{window.chrome.webview.postMessage({command,requestId,...payload(extra)});}catch(error){desktop.pending.delete(requestId);desktop.requests.delete(requestId);toast('Не удалось отправить команду: '+error.message,true);return false;}
  updateAvailability();return requestId;
}
function findNative(title,section){const matches=nativeActions(section).filter(a=>normal(a.title)===normal(title));return matches.find(a=>a.enabled)||matches[0];}
function callNative(title,extra={},section=sectionNames[state.section]){
  const action=findNative(title,section);if(!action){toast('Команда недоступна: '+title,true);return;}
  const selection=payloadForSection(sectionKey(section),extra),reason=nativeUnavailable(action,selection);if(reason){toast(reason,true);return;}
  closeModal();closeMenu();host('native',{...selection,actionId:action.id});
}
function commandGroup(action){
  const title=normal(action.title),section=action.section;
  if(section==='Меню')return /резерв|архив|перенос|копию|экспорт/i.test(title)?'Перенос и резерв':/парол|защита|PIN|Hello|блок|ключ-файл/i.test(title)?'Доступ и защита':/настро|уведом|трей|браузер|горяч|тем/i.test(title)?'Настройки':'Приложение';
  if(section==='Файлы')return /Зашифровать|Расшифровать|Без WinUp/.test(title)?'Пакеты':/Создать хранилище|Добавить существующее|^Открыть$|Заблокировать хранилище|Проводнике/.test(title)?'Хранилище':/Назад|Новая папка|Добавить файлы|Добавить папку|Выгрузить|Удалить выбранное/.test(title)?'Файлы':'Управление';
  if(section==='WinGet')return /набор/.test(title)?'Мой набор':/Установить|Обновить отмеченные|Отметить все|Тихо/.test(title)?'Установка':'Поиск';
  if(section==='Установка')return /Добавить|Найти/.test(title)?'Добавление':/Установить|Тихо|Отметить/.test(title)?'Установка':'Список';
  if(section==='Запуск')return title==='Запустить'?'Запуск':'Список';
  if(section==='Скачать')return title==='Открыть сайт'?'Сайт':'Список';
  if(section==='Пароли')return /Войти|Копировать|Код 2FA|Автоввод в приложение/.test(title)?'Вход':/базы|Группы|Объединить|Папка резерва|Заблокировать|Код восстановления|горячая клавиша/.test(title)?'База':'Записи';
  return section==='2FA'?(/Копировать/.test(title)?'Код':'Аккаунты'):(/Открыть|Обновить|Windows/.test(title)?'Вход':'Ключи');
}
function nativeUnavailable(action,selection=payloadForSection(sectionKey(action.section))){
  if(!action.enabled)return 'Сейчас недоступно';
  const title=normal(action.title),key=sectionKey(action.section);
  if(operationBusy()&&!title.startsWith('Отмен'))return 'Идёт операция';
  if(['passwords','otp','passkeys'].includes(key)&&state.vaultLocked&&!/^Открыть(?: базу)?$|^Создать(?: базу)?$/.test(title))return 'Откройте базу';
  const required={passwords:['Войти','Копировать логин','Копировать пароль','Код 2FA','Изменить','Удалить','Закрепить / открепить','Автоввод в приложение','Дополнительные поля','Вложения','Ссылки между полями'],otp:['Копировать код','Изменить','Удалить'],passkeys:['Открыть сайт','Удалить ключ'],run:['Запустить','Изменить','Убрать из списка'],install:['Изменить','Убрать из списка'],download:['Открыть сайт','Изменить','Удалить']};
  const id={passwords:selection.selected,otp:selection.otp,passkeys:selection.key,run:selection.app,install:selection.app,download:selection.link}[key];
  const source={passwords:state.accounts,otp:state.otps,passkeys:state.passkeys,run:state.apps,install:state.installers,download:state.links}[key];
  const item=source?.find(a=>a.id===id);
  if(required[key]?.includes(title)&&!item)return 'Выберите запись';
  if(key==='run'&&title==='Запустить'&&!item?.exists)return 'Файл не найден';
  if(['Установить отмеченные','Обновить отмеченные','Добавить в мой набор','Убрать из набора','Изменить отмеченные','Войти в отмеченные'].includes(title)&&!selection.checked?.length)return 'Отметьте нужные записи';
  if(key==='files'){
    const vault=currentVault();
    if(['Назад','Новая папка','Добавить файлы','Добавить папку','Выгрузить','Удалить выбранное','История файлов','В Проводнике','Заблокировать хранилище'].includes(title)&&(!vault||vault.locked))return 'Откройте хранилище';
    if(title==='Назад'&&!state.path)return 'Вы находитесь в корне';
    if(['Выгрузить','Удалить выбранное'].includes(title)&&!selection.files?.length)return 'Выберите файлы';
    if(vault?.readonly&&['Новая папка','Добавить файлы','Добавить папку','Удалить выбранное'].includes(title))return 'Хранилище открыто только для чтения';
  }
  return '';
}
function commandSelection(action){return desktop.menuSelection?.section===action.section?desktop.menuSelection:payloadForSection(sectionKey(action.section));}
function nativeRows(actions,query=''){
  const terms=query.trim().toLocaleLowerCase('ru').replace(/ё/g,'е').split(/\s+/).filter(Boolean),unique=new Map(),groups=new Map();
  for(const action of actions){const key=action.section+'\0'+normal(action.title);if(!unique.has(key)||!unique.get(key).enabled&&action.enabled)unique.set(key,action);}
  for(const action of unique.values()){
    const group=commandGroup(action),text=(action.title+' '+action.section+' '+group).toLocaleLowerCase('ru').replace(/ё/g,'е');if(!terms.every(term=>text.includes(term)))continue;
    const label=(desktop.commandScope?'':action.section+' · ')+group;if(!groups.has(label))groups.set(label,[]);groups.get(label).push(action);
  }
  if(!groups.size)return `<div class="no-results" role="status">${desktop.ready?(terms.length?'Действие не найдено. Измените запрос.':'В этом разделе пока нет действий.'):'Загрузка действий…'}</div>`;
  return [...groups].map(([label,items])=>`<section class="command-group" aria-label="${esc(label)}"><h3>${esc(label)}<span>${items.length}</span></h3>${items.map(action=>{const reason=nativeUnavailable(action,commandSelection(action));return `<button class="command-row" data-action="native" data-native="${esc(action.id)}" data-native-section="${esc(action.section)}" ${reason?'disabled':''}>${icon(action.check?'check':'arrow')}<span class="command-label">${esc(action.title)}</span>${reason?`<small class="command-unavailable">${esc(reason)}</small>`:''}</button>`;}).join('')}</section>`).join('');
}
function refreshCommands(force=false){
  const results=$('#native-results');if(!results||!$('#modal').open)return;
  const query=$('#native-search')?.value||'',markup=nativeRows(desktop.commandScope?nativeActions(desktop.commandScope):desktop.actions,query);
  if(!force&&markup===desktop.commandStructure)return;desktop.commandStructure=markup;
  const focus=document.activeElement?.dataset.native,scroll=$('#modal-body').scrollTop;results.innerHTML=markup;
  if(focus)results.querySelector(`[data-native="${CSS.escape(focus)}"]`)?.focus({preventScroll:true});$('#modal-body').scrollTop=scroll;
  const count=$$('#native-results .command-row').length;$('#command-count').textContent=`Найдено действий: ${count}`;
}
function showCommands(section,selection){
  desktop.commandScope=section;desktop.menuSelection=selection;desktop.commandStructure='';
  modal(section==='Меню'?'Действия приложения':section?'Действия · '+section:'Все действия','<label class="form-field command-search">Найти действие<input id="native-search" autocomplete="off" placeholder="Например, резерв или шифрование"></label><div class="command-summary"><span id="command-count" role="status" aria-live="polite"></span><span>↑ ↓ · выбор, Enter · выполнить</span></div><div class="command-results" id="native-results"></div>',null,'',true);
  refreshCommands(true);$('#native-search').focus();
}
function nativeMenu(section=sectionNames[state.section],selection={}){showCommands(section,payloadForSection(sectionKey(section),selection));}
function desktopCommands(){showCommands(null,payload());}
function applyNative(data,request=null,success=true){if(state.fileVault!==data.fileVault||state.path!==data.path)state.fileSelection.clear();desktop.snapshot=data;desktop.actions=data.actions;state.vaultLocked=data.locked;state.database=data.database;state.browser=data.browser;state.accounts=data.accounts;state.otps=data.otps;state.passkeys=data.passkeys;state.apps=data.apps;state.installers=data.installers;state.packages=data.packages;state.links=data.links;state.vaults=data.vaults;state.files=data.files;state.fileVault=data.fileVault;state.path=data.path;state.groups=data.groups;state.running=data.busy;state.settings={...state.settings,...data.settings};state.activity=data.activity.map(text=>({text,time:''}));if(data.locked)purgeSecrets(false);if(desktop.secret){let a=state.accounts.find(a=>a.id===desktop.secret.id);if(a)a.password=desktop.secret.value;else purgeSecrets(false);}
  if(['all','set','updates'].includes(data.wingetMode)&&(!desktop.ready||request&&['native','winget-mode','winget-search'].includes(request.command))){if(state.wgMode!==data.wingetMode&&state.section==='winget')state.query='';state.wgMode=data.wingetMode;}
  if(success&&data.selection&&request&&['native','winget-search','winget-mode','file-select','file-open-item'].includes(request.command)){
    const selection=data.selection,key=sectionKey(request.section);
    if(key==='passwords')state.selected=selection.passwords||null;
    for(const section of ['otp','passkeys','run','install','download'])if(section===key&&typeof selection[section]==='string')desktop.selection[section]=selection[section];
    const checked={passwords:'checkedPasswords',install:'checkedInstallers',winget:'checkedPackages'}[key];
    if(checked&&Array.isArray(selection[checked])){desktop.checked[key]=new Set(selection[checked]);if(state.section===key)state.checked=new Set(selection[checked]);}
    if(key==='files'&&Array.isArray(selection.files))state.fileSelection=new Set(selection.files);
  }
  const collections={passwords:state.accounts,install:state.installers,winget:state.packages};
  for(const [key,items]of Object.entries(collections)){const ids=new Set(items.map(item=>item.id));if(desktop.checked[key])desktop.checked[key]=new Set([...desktop.checked[key]].filter(id=>ids.has(id)));if(state.section===key)state.checked=new Set([...state.checked].filter(id=>ids.has(id)));}
  const fileIds=new Set(state.files.map(file=>file.id));state.fileSelection=new Set([...state.fileSelection].filter(id=>fileIds.has(id)));
  if(desktop.secret&&desktop.secret.id!==state.selected)purgeSecrets(false);
  document.documentElement.dataset.theme=data.theme;
  const stable=JSON.stringify({...data,otps:data.otps.map(o=>({...o,code:'',left:0})),status:'',fileState:'',actions:[],activity:[],busy:false,selection:null});
  const changed=stable!==desktop.structure;desktop.structure=stable;desktop.ready=true;
  if((changed||request&&request.command!=='refresh')&&!$('#modal').open)render();updateAvailability();refreshCommands();tickOtp();const dot=$('[data-action="extension"] .status-dot');if(dot){dot.style.background=data.extensionConnected?'var(--green)':'var(--muted)';dot.title=data.extensionConnected?'Подключено к этой копии':'Не подключено к этой копии';}$('#db-state').textContent=data.locked?'База закрыта':'База открыта';$('#desktop-status')?.replaceChildren(document.createTextNode((state.section==='files'?data.fileState:data.status)||''));
}
function purgeSecrets(repaint=true){clearTimeout(desktop.secretTimer);desktop.secret=null;state.revealed=false;state.accounts.forEach(a=>a.password='');if(repaint&&!$('#modal').open)render();}
if(window.chrome?.webview)window.chrome.webview.addEventListener('message',event=>{let msg=event.data;if(msg.type==='purge'){purgeSecrets(false);state.vaultLocked=true;state.accounts=[];state.otps=[];state.passkeys=[];state.selected=null;desktop.checked.passwords=new Set();if(state.section==='passwords')state.checked.clear();closeModal();render();return;}if(msg.type==='secret'){purgeSecrets(false);desktop.secret={id:msg.id,value:msg.value};let a=state.accounts.find(a=>a.id===msg.id);if(a)a.password=msg.value;state.revealed=true;render();desktop.secretTimer=setTimeout(()=>purgeSecrets(),30000);return;}if(msg.type==='state'){const request=desktop.requests.get(msg.requestId),settingsReply=desktop.settingsRequest?.id===msg.requestId,settingsOpen=settingsReply&&desktop.settingsRequest.field.isConnected&&$('#modal').open;desktop.pending.delete(msg.requestId);desktop.requests.delete(msg.requestId);if(settingsReply)desktop.settingsRequest=null;applyNative(msg.data,request,!msg.error);if(msg.error){if($('#modal').open&&(!settingsReply||settingsOpen))error(msg.error);else toast(msg.error,true);}else if(settingsOpen)closeModal();}});
otpCode=id=>state.otps.find(o=>o.id===id)?.code||'';
tickOtp=function(){for(const node of $$('[data-otp]')){let o=state.otps.find(o=>o.id===node.dataset.otp);if(o)node.textContent=prettyCode(o.code);}for(const node of $$('[data-otp-left],[data-countdown]')){const id=node.dataset.otpLeft||node.parentElement.querySelector('[data-otp]')?.dataset.otp;let o=state.otps.find(o=>o.id===id);if(o){node.textContent=o.left+' с';node.style.color=o.left<=5?'var(--red)':'';}}};
lockScreen=()=>`<div class="lock-screen"><div class="lock-art">${icon('lock')}</div><h2>${desktop.snapshot?.baseExists?'База заблокирована':'Создайте базу паролей'}</h2><p>Пароли, коды 2FA и ключи доступа открываются одним паролем. Файловые хранилища управляются отдельно.</p>${btn('unlock',desktop.snapshot?.baseExists?'Открыть базу':'Создать базу','key','primary')}<div class="toolbar">${btn('settings','Настройки доступа','settings')}${btn('help','Инструкция','help')}</div></div>`;
const originalRender=render;
render=function(){originalRender();$('#db-state').textContent=state.vaultLocked?'База закрыта':'База открыта';const footer=$('.main-footer span');if(footer)footer.innerHTML='<i></i>Данные этой копии WinUp';const old=$('#desktop-status');if(!old){$('#content').insertAdjacentHTML('beforeend','<p id="desktop-status" class="muted" role="status" style="margin-top:18px;overflow-wrap:anywhere"></p>');}$('#desktop-status').textContent=(state.section==='files'?desktop.snapshot?.fileState:desktop.snapshot?.status)||'';if(state.section==='passwords'&&!state.vaultLocked)$('#head-actions').insertAdjacentHTML('afterbegin',btn('lock-secrets','Заблокировать базу','lock','small'));if(state.section==='otp'||state.section==='passkeys')$('#head-actions').insertAdjacentHTML('afterbegin',btn('lock-secrets','Заблокировать базу','lock','small'));if(state.section==='files')$('#head-actions').insertAdjacentHTML('afterbegin',btn('lock-files','Закрыть хранилище','lock','small'));$('#head-actions').insertAdjacentHTML('beforeend',btn('section-actions','Все действия','more','small'));hydrate();tickOtp();};
const originalDetail=renderAccountDetail;
function decorateSelection(){
  const s=state.section;
  const source={otp:state.otps,passkeys:state.passkeys,run:state.apps,install:state.installers,download:state.links}[s];
  let item;
  if(source){
    const query=state.query.toLowerCase();
    const items=source.filter(a=>({otp:(a.name+' '+a.login),passkeys:(a.rp+' '+a.login),run:(a.name+' '+a.description),install:(a.name+' '+a.file),download:(a.name+' '+a.description)}[s]||'').toLowerCase().includes(query));
    if(!items.some(a=>a.id===desktop.selection[s]))desktop.selection[s]=items[0]?.id||'';
    const selector=s==='otp'?'.otp-card':s==='run'?'.app-card':'#content tbody tr';
    $$(selector).forEach((row,index)=>{const a=items[index];if(!a)return;row.dataset.action='select-item';row.dataset.section=s;row.dataset.id=a.id;row.tabIndex=0;row.setAttribute('role','button');row.setAttribute('aria-label','Выбрать '+(a.name||a.rp)+' '+(a.login||''));row.setAttribute('aria-pressed',String(a.id===desktop.selection[s]));row.classList.toggle('selected',a.id===desktop.selection[s]);});
    item=items.find(a=>a.id===desktop.selection[s]);
  }else if(s==='passwords')item=selected();
  let actions='';
  if(item){
    actions='<span class="selection-name" title="'+esc(item.name||item.rp)+'">Выбрано: '+esc(item.name||item.rp)+'</span>';
    const title={passwords:'Изменить...',otp:'Изменить...',run:'Изменить...',install:'Изменить...',download:'Изменить...'}[s];
    if(title){const a=nativeActions().find(a=>normal(a.title)===normal(title));if(a)actions+=btn('native','Изменить','edit','small',`data-native="${esc(a.id)}" data-native-section="${esc(a.section)}"`);}
    const removeTitle=s==='passkeys'?'Удалить ключ':['run','install'].includes(s)?'Убрать из списка':'Удалить';
    const remove=findNative(removeTitle,sectionNames[s]);
    if(remove)actions+=btn('native',['run','install'].includes(s)?'Убрать из списка':'Удалить','trash','small',`data-native="${esc(remove.id)}" data-native-section="${esc(remove.section)}"`);
    actions+=btn('selection-menu','Действия с выбранным','more','small');
  }
  if(s==='passwords'&&state.checked.size)actions+=`<span>Отмечено: ${state.checked.size}</span>`+btn('bulk','Изменить отмеченные','edit','small')+btn('uncheck','Снять отметки','x','small');
  if(s==='install'&&state.checked.size)actions+=`<span>Отмечено установщиков: ${state.checked.size}</span>`+btn('uncheck','Снять отметки','x','small');
  if(s==='winget'&&state.checked.size)actions=`<span class="selection-name">Отмечено пакетов: ${state.checked.size}</span>`+btn('wg-upgrade','Обновить отмеченные','refresh','small')+btn('wg-set-add','В мой набор','plus','small')+btn('wg-set-remove','Убрать из набора','x','small')+btn('uncheck','Снять отметки','x','small');
  if(s==='files'&&state.fileSelection.size)actions=`<span class="selection-name">Выбрано файлов: ${state.fileSelection.size}</span>`+btn('file-export','Выгрузить','download','small')+btn('file-delete','Удалить','trash','small');
  $('#selection-actions').innerHTML=state.vaultLocked&&['passwords','otp','passkeys'].includes(s)?'':actions;
  if(s==='files'&&currentVault()?.readonly)for(const b of $$('#selection-actions [data-action="file-delete"]'))b.disabled=true;
  requestAnimationFrame(()=>document.documentElement.style.setProperty('--dock-height',$('.action-dock').offsetHeight+'px'));
}
const dockObserver=new ResizeObserver(()=>document.documentElement.style.setProperty('--dock-height',$('.action-dock').offsetHeight+'px'));dockObserver.observe($('.action-dock'));
const desktopRender=render;
render=function(){const oldCard=$('.account-detail'),oldScroll=oldCard?.querySelector('.detail-scroll'),cardId=oldCard?.dataset.id,cardScroll=oldScroll?.scrollTop||0;const previous=state.selected;desktopRender();if(previous!==state.selected&&state.revealed){purgeSecrets(false);desktopRender();}const silent=$('#silent');if(silent)silent.checked=state.silent;const v=currentVault();if(state.section==='files'&&v&&!v.locked&&v.readonly){for(const action of ['file-add','folder-add','file-new-folder','file-delete'])for(const button of $$('[data-action="'+action+'"]'))button.disabled=true;}for(const button of $$('[data-action="lock-files"]'))button.disabled=!v||v.locked;for(const button of $$('[data-action="password-menu"],#head-actions [data-action="files-global-menu"]'))button.remove();decorateSelection();const card=$('.account-detail');if(card&&card.dataset.id===cardId)card.querySelector('.detail-scroll').scrollTop=cardScroll;};
renderAccountDetail=function(a){let markup=originalDetail(a).replace('<aside class="panel"','<aside class="panel account-detail" data-id="'+esc(a.id)+'"').replace('<div class="detail-fields">','<div class="detail-scroll" tabindex="0" role="region" aria-label="Поля выбранного аккаунта"><div class="detail-fields">').replace('<div class="detail-actions">','</div><div class="detail-actions">');if(!state.revealed)markup=markup.replace('••••••••••••••••','••••••••••••');return markup;};
renderOtp=function(){let items=state.otps.filter(o=>(o.name+' '+o.login).toLowerCase().includes(state.query.toLowerCase()));return searchBar('Найти сервис или аккаунт…')+`<div class="grid">${items.map(o=>`<article class="panel otp-card"><div class="card-header">${logo(o.name)}<div><h3>${esc(o.name)}</h3><p>${esc(o.login)}</p></div>${ib('otp-menu','Действия с 2FA','more',`data-id="${esc(o.id)}"`)}</div><div class="otp-code"><span data-otp="${esc(o.id)}">${prettyCode(o.code)}</span>${ib('otp-copy','Копировать код','copy',`data-id="${esc(o.id)}"`)}</div><div class="card-bottom"><span data-otp-left="${esc(o.id)}">${o.left} с</span><small>${esc(o.algorithm)} · ${o.digits} цифр · ${o.period} с</small></div></article>`).join('')}</div>`+(!items.length?empty('Кодов пока нет','Добавьте ключ 2FA или импортируйте его из другого приложения.','otp-add','Добавить 2FA'):'');};
renderPasskeys=function(){let items=state.passkeys.filter(k=>(k.rp+' '+k.login).toLowerCase().includes(state.query.toLowerCase()));return `<div class="hint-bar">${icon('fingerprint')}<span>Создайте ключ на сайте и выберите WinUp в расширении или в системном окне Windows.</span>${btn('provider','Ключи в Windows','laptop','small')}</div>`+searchBar('Найти сайт или аккаунт…')+`<div class="panel table-wrap"><table><thead><tr><th>САЙТ</th><th>АККАУНТ</th><th></th></tr></thead><tbody>${items.map(k=>`<tr><td>${esc(k.rp)}</td><td>${esc(k.login)}</td><td>${btn('passkey-login','Войти','arrow','small',`data-id="${esc(k.id)}"`)}${ib('passkey-menu','Действия с ключом','more',`data-id="${esc(k.id)}"`)}</td></tr>`).join('')}</tbody></table></div>`+(!items.length?empty('Ключей пока нет','Откройте сервис и создайте ключ доступа.','passkey-add','Добавить ключ'):'');};
renderApps=function(){let items=state.apps.filter(a=>(a.name+' '+a.description).toLowerCase().includes(state.query.toLowerCase()));return searchBar('Найти программу…')+`<div class="app-grid">${items.map(a=>`<article class="panel app-card"><div class="card-header">${logo(a.name)}<div><h3>${esc(a.name)}</h3><p>${esc(a.path)}</p></div>${ib('app-menu','Настроить программу','more',`data-id="${esc(a.id)}"`)}</div><p class="description">${esc(a.description||a.note||'')}</p><div class="app-foot"><span class="tag ${a.exists?'green':'amber'}">${a.exists?'Найдена':'Файл не найден'}</span>${btn('app-launch','Запустить','play','small',`data-id="${esc(a.id)}"`)}</div></article>`).join('')}</div>`+(!items.length?empty('Добавьте программы','Выберите установленные или переносные приложения.','app-add','Добавить программу'):'');};
packageItems=()=>state.packages.filter(p=>(p.name+' '+p.id).toLowerCase().includes(state.query.toLowerCase()));
const originalWinget=renderWinget;
renderWinget=()=>originalWinget().replace('Каталог и версии здесь учебные. Кнопки показывают очередь и результаты; программы на ПК не устанавливаются.','Каталог WinGet загружается по запросу. Установка выполняется с сайтов разработчиков и может потребовать подтверждения Windows.');
renderFiles=function(){let v=currentVault();return `<div class="file-layout"><div class="panel vaults">${state.vaults.map(v=>`<button class="vault-card ${v.id===state.fileVault?'active':''}" data-action="vault-select" data-id="${esc(v.id)}">${icon('folder')}<span><b>${esc(v.name)}</b><small>${v.locked?'Закрыто':esc(v.drive||'Открыто')}</small></span></button>`).join('')}${btn('vault-attach','Добавить существующее','plus')}</div><div class="panel">${v?`<div class="panel-heading"><div><h3>${esc(v.name)}</h3><small class="muted">${esc(v.path)}</small></div>${ib('vault-menu','Настройки хранилища','more')}</div>${v.locked?`<div class="lock-screen"><h2>Хранилище закрыто</h2>${btn('vault-unlock','Открыть хранилище','key','primary')}</div>`:`<div class="toolbar">${btn('file-up','Назад','back','small')}<span class="muted">/${esc(state.path)}</span><span class="spacer"></span>${btn('vault-explorer','В Проводнике','folder','small')}${btn('lock-files','Заблокировать хранилище','lock','small')}</div><div class="toolbar">${btn('file-add','Добавить файлы','plus','small')}${btn('folder-add','Добавить папку','folder','small')}${btn('file-new-folder','Новая папка','plus','small')}${btn('file-export','Выгрузить','download','small')}${btn('file-history','История','clock','small')}${btn('file-delete','Удалить выбранное','trash','small')}</div><div class="table-wrap"><table><thead><tr><th></th><th>НАЗВАНИЕ</th><th>РАЗМЕР</th></tr></thead><tbody>${state.files.map(f=>`<tr><td><input type="checkbox" data-file-check="${esc(f.id)}" aria-label="Выбрать ${esc(f.name)}" ${state.fileSelection.has(f.id)?'checked':''}></td><td><button class="command-row" data-action="file-open" data-id="${esc(f.id)}">${icon(f.folder?'folder':'file')}${esc(f.name)}</button></td><td>${esc(f.size)}</td></tr>`).join('')}</tbody></table></div>`}`:empty('Добавьте хранилище','Создайте новое или откройте существующее.','vault-create','Создать хранилище')}</div></div><div class="package-actions">${btn('pack-file','Зашифровать файлы','lock')}${btn('pack-folder','Зашифровать папку','folder')}${btn('package-decrypt','Расшифровать пакет','key')}${btn('independent','Открыть без WinUp','help')}</div>`;};
const direct={
  'account-add':['Добавить...','Пароли'],'account-edit':['Изменить...','Пароли'],'account-delete':['Удалить','Пароли'],'pin':['Закрепить / открепить','Пароли'],'import':['Импорт паролей…','Пароли'],'history':['История / корзина…','Пароли'],'trash':['История / корзина…','Пароли'],'attachments':['Вложения…','Пароли'],'custom-fields':['Дополнительные поля…','Пароли'],'references':['Ссылки между полями…','Пароли'],'autotype':['Автоввод в приложение…','Пароли'],'bulk':['Изменить отмеченные…','Пароли'],'groups':['Группы…','Пароли'],'addresses':['Проверить адреса…','Пароли'],'merge':['Объединить копии базы…','Пароли'],'generator':['Генератор...','Пароли'],'choose-browser':['Изменить...','Пароли'],
  'otp-add':['Добавить...','2FA'],'otp-import':['Импорт из другого приложения...','2FA'],'passkey-add':['Добавить ключ…','Ключи доступа'],'provider':['Ключи в Windows…','Ключи доступа'],
  'vault-create':['Создать хранилище','Файлы'],'vault-attach':['Добавить существующее','Файлы'],'vault-unlock':['Открыть','Файлы'],'lock-files':['Заблокировать хранилище','Файлы'],'vault-lock':['Заблокировать хранилище','Файлы'],'vault-explorer':['В Проводнике','Файлы'],'file-add':['Добавить файлы','Файлы'],'folder-add':['Добавить папку','Файлы'],'file-new-folder':['Новая папка','Файлы'],'file-up':['Назад','Файлы'],'file-export':['Выгрузить…','Файлы'],'file-history':['История файлов…','Файлы'],'file-delete':['Удалить выбранное','Файлы'],'pack-file':['Зашифровать файлы…','Файлы'],'pack-folder':['Зашифровать папку…','Файлы'],'package-decrypt':['Расшифровать пакет…','Файлы'],'independent':['Без WinUp…','Файлы'],
  'app-add':['Добавить файлы...','Запуск'],'installer-add':['Добавить файлы...','Установка'],'installer-folder':['Добавить папку...','Установка'],'installer-scan':['Найти установщики на ПК...','Установка'],'installer-discover':['Найти новые в apps','Установка'],'installer-run':['Установить отмеченные','Установка'],'wg-run':['Установить отмеченные','WinGet'],'wg-upgrade':['Обновить отмеченные','WinGet'],'wg-updates':['Проверить обновления','WinGet'],'wg-set-add':['Добавить в мой набор','WinGet'],'wg-set-remove':['Убрать из набора','WinGet'],
  'link-add':['Добавить...','Скачать'],'export':['Экспорт паролей...','Меню'],'updates':['Обновления компонентов...','Меню'],'about':['О программе','Меню'],'help':['Справка (инструкция)','Меню'],'wizard':['Мастер первого запуска...','Меню'],'share':['Подготовить копию для передачи...','Меню'],'transfer':['Архив для переноса на другой ПК...','Меню'],'kdf':['Защита от подбора пароля...','Меню'],'pin-configure':['PIN-код быстрой разблокировки...','Меню'],'hello-configure':['Вход по Windows Hello...','Меню']};
for(const [action,[title,section]]of Object.entries(direct))A[action]=()=>callNative(title,{},section);
Object.assign(A,{
  native:e=>{const action=desktop.actions.find(a=>a.id===e.dataset.native);if(!action)return;const section=sectionKey(action.section);const selection=$('#modal').open?commandSelection(action):payloadForSection(section);const reason=nativeUnavailable(action,selection);if(reason){toast(reason,true);return;}closeModal();if(sections[section]&&section!==state.section)navigate(section);host('native',{...selection,actionId:action.id});},'modal-submit':()=>modalSubmit?.(),close:closeModal,
  'select-item':e=>{desktop.selection[e.dataset.section]=e.dataset.id;render();},'selection-menu':()=>nativeMenu(),
  nav:e=>{purgeSecrets(false);closeModal();navigate(e.dataset.section);host('refresh');},'select-account':e=>{purgeSecrets(false);state.selected=e.dataset.id;render();if(matchMedia('(max-width:760px)').matches)document.querySelector('.account-detail')?.scrollIntoView({block:'start',behavior:'instant'});},'lock-secrets':()=>{purgeSecrets();host('lock-secrets');},'lock-all':()=>{purgeSecrets();host('lock-all');},unlock:()=>host('unlock'),
  'reveal':()=>state.revealed?purgeSecrets():host('reveal'),'copy-login':()=>host('copy-login'),'copy-password':()=>host('copy-password'),'copy-extra':()=>host('copy-metadata',{text:selected()?.extraLogin||''}),'copy-otp':()=>host('copy-account-otp'),'copy-url':()=>host('copy-metadata',{text:selected()?.loginUrl||selected()?.url||''}),
  'login':()=>host('login'),'login-checked':()=>host('login-checked'),'filter-all':()=>{state.pinned=false;render();},'filter-pinned':()=>{state.pinned=true;render();},'filter-reset':()=>{state.query=state.category=state.type=state.group=state.tag='';state.pinned=false;render();},uncheck:()=>{state.checked.clear();render();},sort:()=>{state.sort=state.sort==='name'?'recent':'name';render();},
  'filter-more':()=>modal('Группы и метки',`<div class="form-grid">${dropdown('group','Группа',[['','Все группы'],...state.groups],state.group,true)}${dropdown('tag','Метка',[['','Все метки'],...new Set(state.accounts.flatMap(a=>a.tags))],state.tag,true)}</div>`,()=>{state.group=value('group');state.tag=value('tag');closeModal();render();},'Применить'),
  'record-history':()=>callNative('История / корзина…',{},'Пароли'),'account-more':()=>nativeMenu('Пароли'),'password-menu':()=>nativeMenu('Пароли'),'database':()=>nativeMenu('Пароли'),'section-actions':()=>nativeMenu(),'files-global-menu':()=>nativeMenu('Файлы'),'vault-menu':()=>nativeMenu('Файлы'),
  'otp-copy':e=>host('copy-otp',{otp:e.dataset.id}),'otp-menu':e=>nativeMenu('2FA',{otp:e.dataset.id}),'passkey-menu':e=>nativeMenu('Ключи доступа',{key:e.dataset.id}),'passkey-login':e=>callNative('Открыть сайт',{key:e.dataset.id},'Ключи доступа'),
  'vault-select':e=>host('file-select',{folder:e.dataset.id}),'file-open':e=>host('file-open-item',{files:[e.dataset.id]}),'app-menu':e=>nativeMenu('Запуск',{app:e.dataset.id}),'app-launch':e=>callNative('Запустить',{app:e.dataset.id},'Запуск'),'installer-menu':e=>nativeMenu('Установка',{app:e.dataset.id}),
  'installer-select-all':()=>{const items=state.installers.filter(i=>(i.name+' '+i.file).toLowerCase().includes(state.query.toLowerCase()));const on=items.some(i=>!state.checked.has(i.id));items.forEach(i=>on?state.checked.add(i.id):state.checked.delete(i.id));render();},'wg-select-all':()=>{const items=packageItems(),on=items.some(i=>!state.checked.has(i.id));items.forEach(i=>on?state.checked.add(i.id):state.checked.delete(i.id));render();},'wg-mode':e=>{if(operationBusy())return;state.wgMode=e.dataset.mode;state.query='';render();host('winget-mode',{mode:e.dataset.mode,query:''});},'wg-search':()=>host('winget-search',{query:state.query}),
  'link-open':e=>callNative('Открыть сайт',{link:e.dataset.id},'Скачать'),'link-menu':e=>nativeMenu('Скачать',{link:e.dataset.id}),'recovery':()=>callNative('Изменить...',{},'Пароли'),
  'extension':()=>modal('Расширение браузера','<p class="modal-description">Подключение связывает расширение с этой копией WinUp. Если расширение подключено к другой копии, его подключение переключится сюда.</p>'+btn('extension-configure','Открыть настройки расширения','puzzle','primary')),'extension-configure':()=>callNative('Расширение для браузера...',{},'Меню'),
  theme:()=>host('theme',{theme:document.documentElement.dataset.theme==='dark'?'light':'dark'}),settings:desktopSettings,'activity':()=>modal('Журнал действий','<pre class="activity-log">'+esc(desktop.snapshot?.activity.join('\n')||'Записей пока нет')+'</pre>'),commands:desktopCommands
});
function desktopSettings(){const s=desktop.snapshot?.settings||{};modal('Настройки',`<div class="form-grid">${field('minutes','Блокировать базу после простоя, мин',s.autoLock||10,'number')}${dropdown('browser','Браузер для сайтов',[['','По умолчанию'],...(desktop.snapshot?.browsers||[])],state.browser||'')}</div>${checkbox('tray','Сворачивать в трей',s.tray)}${checkbox('notify','Уведомлять о вставке пароля',s.notify)}<div class="notice">Пароль базы, ключ-файл, Windows Hello, PIN, резервирование и обновления доступны в действиях приложения.</div><div class="toolbar">${btn('application-actions','Действия приложения','settings')}${btn('theme','Сменить тему','sun')}</div>`,()=>{const minutes=Number(value('minutes'));if(!Number.isInteger(minutes)||minutes<1||minutes>1440){error('Время блокировки: целое число от 1 до 1440 минут.');$('[name="minutes"]')?.focus();return;}const id=host('settings',{minutes,browser:value('browser'),tray:check('tray'),notify:check('notify')});if(id)desktop.settingsRequest={id,field:$('[name="minutes"]')};},'Сохранить');for(const name of ['minutes','browser','tray','notify'])$('[name="'+name+'"]')?.setAttribute('id',name);const minutes=$('[name="minutes"]');minutes.min='1';minutes.max='1440';minutes.step='1';minutes.required=true;updateAvailability();}
A['application-actions']=()=>nativeMenu('Меню');
document.addEventListener('click',event=>{if(event.target.closest('button:disabled,[aria-disabled="true"],input[type=checkbox]'))return;const el=event.target.closest('[data-action]');if(!el)return;const action=A[el.dataset.action];if(action)action(el);else nativeMenu();});
document.addEventListener('input',event=>{if(event.target.id==='native-search'){desktop.commandStructure='';refreshCommands(true);$('#modal-body').scrollTop=0;}if(event.target.id==='search'){state.query=event.target.value;render();}});
document.addEventListener('change',event=>{const e=event.target;if(e.id==='category-filter'){state.category=e.value;render();}if(e.id==='type-filter'){state.type=e.value;render();}if(e.dataset.check){state.selected=e.dataset.check;e.checked?state.checked.add(e.dataset.check):state.checked.delete(e.dataset.check);render();}if(e.hasAttribute('data-check-all')){for(const a of filteredAccounts())e.checked?state.checked.add(a.id):state.checked.delete(a.id);render();}for(const key of ['packageCheck','installerCheck'])if(e.dataset[key]){if(key==='installerCheck')desktop.selection.install=e.dataset[key];e.checked?state.checked.add(e.dataset[key]):state.checked.delete(e.dataset[key]);}if(e.dataset.fileCheck)e.checked?state.fileSelection.add(e.dataset.fileCheck):state.fileSelection.delete(e.dataset.fileCheck);decorateSelection();});
document.addEventListener('keydown',event=>{
  if(event.isComposing)return;
  if(event.key==='Escape'){event.preventDefault();closeModal();closeMenu();return;}
  const commandKey=event.ctrlKey||event.metaKey;
  if(commandKey&&event.key.toLowerCase()==='k'){event.preventDefault();desktopCommands();return;}
  if(commandKey&&event.key.toLowerCase()==='l'){event.preventDefault();A['lock-all']();return;}
  if(commandKey&&event.key.toLowerCase()==='f'&&!$('#modal').open){const search=$('#search');if(search){event.preventDefault();search.focus();search.select();}return;}
  if(event.target.id==='search'&&event.key==='Enter'&&state.section==='winget'){event.preventDefault();A['wg-search']();return;}
  if($('#modal').open&&(event.target.id==='native-search'||event.target.closest('#native-results'))){
    const rows=$$('#native-results .command-row:not(:disabled)'),index=rows.indexOf(event.target.closest('.command-row'));let next;
    if(event.key==='ArrowDown')next=rows[index<0?0:Math.min(index+1,rows.length-1)];
    if(event.key==='ArrowUp')next=rows[index<0?rows.length-1:Math.max(0,index-1)];
    if(index>=0&&event.key==='Home')next=rows[0];if(index>=0&&event.key==='End')next=rows.at(-1);
    if(next){event.preventDefault();next.focus();next.scrollIntoView({block:'nearest'});return;}
    if(event.key==='Enter'&&event.target.id==='native-search'){event.preventDefault();rows[0]?.click();return;}
    if(index>=0&&['Enter',' '].includes(event.key)){event.preventDefault();rows[index].click();return;}
  }
  const row=event.target.matches('[role="button"][data-action]')?event.target:null;
  if(row&&!event.target.closest('[aria-disabled="true"]')){
    if(['Enter',' '].includes(event.key)){event.preventDefault();A[row.dataset.action]?.(row);return;}
    if(['ArrowDown','ArrowUp','Home','End'].includes(event.key)){
      const rows=$$(`[data-action="${row.dataset.action}"]`),index=rows.indexOf(row),target=event.key==='Home'?rows[0]:event.key==='End'?rows.at(-1):rows[Math.max(0,Math.min(rows.length-1,index+(event.key==='ArrowDown'?1:-1)))];
      if(target){event.preventDefault();const id=target.dataset.id,action=target.dataset.action;A[action]?.(target);const current=$(`[data-action="${action}"][data-id="${CSS.escape(id)}"]`);current?.focus({preventScroll:true});current?.scrollIntoView({block:'nearest'});}
    }
  }
});
window.addEventListener('blur',()=>purgeSecrets());window.addEventListener('hashchange',()=>{const section=location.hash.slice(1);if(sections[section]&&section!==state.section){purgeSecrets(false);navigate(section);}});
document.addEventListener('change',event=>{if(event.target.id==='silent')state.silent=event.target.checked;});
$('#modal').addEventListener('cancel',event=>{event.preventDefault();closeModal();});
function updateAvailability(){
  const busy=operationBusy();$('#content').setAttribute('aria-busy',String(busy));$('.action-dock').setAttribute('aria-busy',String(busy));
  for(const button of $$('button[data-action]')){
    const actionName=button.dataset.action;let reason=null;
    if(actionName==='native'){
      const action=desktop.actions.find(a=>a.id===button.dataset.native);
      reason=action?nativeUnavailable(action,$('#modal').open&&button.closest('#native-results')?commandSelection(action):payloadForSection(sectionKey(action.section))):'Действие недоступно';
    }else if(direct[actionName]){
      const [title,section]=direct[actionName],action=findNative(title,section),selection=payloadForSection(sectionKey(section));
      if(button.dataset.id){const key=sectionKey(section),field={passwords:'selected',otp:'otp',passkeys:'key',run:'app',install:'app',download:'link'}[key];if(field)selection[field]=button.dataset.id;}
      reason=action?nativeUnavailable(action,selection):(desktop.ready?'Действие недоступно':'Загрузка действий');
    }else if(['lock-secrets','lock-all'].includes(actionName))reason=actionName==='lock-secrets'&&state.vaultLocked?'База уже закрыта':'';
    else if(['unlock','reveal','copy-login','copy-password','copy-extra','copy-otp','copy-url','otp-copy','login','login-checked','theme','extension-configure','modal-submit','wg-search','wg-mode','vault-select','file-open'].includes(actionName)){
      reason=busy?'Идёт операция':'';
      if(actionName==='login-checked'&&!state.checked.size)reason='Отметьте нужные записи';
      if(actionName==='file-open'&&currentVault()?.locked)reason='Откройте хранилище';
    }else if(['installer-select-all','wg-select-all'].includes(actionName))reason=!(actionName==='wg-select-all'?packageItems():state.installers.filter(i=>(i.name+' '+i.file).toLowerCase().includes(state.query.toLowerCase()))).length?'Нет видимых записей':'';
    if(reason!==null){
      if(button.dataset.desktopTitle===undefined)button.dataset.desktopTitle=button.getAttribute('title')||'';
      button.disabled=!!reason;button.title=reason||button.dataset.desktopTitle;
      if(reason)button.setAttribute('aria-disabled','true');else button.removeAttribute('aria-disabled');
    }
  }
  for(const input of $$('[data-check],[data-check-all],[data-package-check],[data-installer-check],[data-file-check]'))input.disabled=busy;
}
function focusRecord(node){
  if(!node||node===document.body)return null;
  const attributes=['id','data-action','data-id','data-section','data-native','data-mode','name','data-check','data-package-check','data-installer-check','data-file-check'];
  const identity=attributes.filter(attribute=>node.hasAttribute(attribute)).map(attribute=>`[${attribute}="${CSS.escape(node.getAttribute(attribute))}"]`).join('');
  if(!identity)return null;
  return {selector:(node.closest('.account-detail')?'.account-detail ':'')+node.tagName.toLowerCase()+identity,start:node.selectionStart,end:node.selectionEnd,direction:node.selectionDirection};
}
const renderDesktopPage=render;
render=function(){
  const active=document.activeElement,focus=focusRecord(active),scrollX=window.scrollX,scrollY=window.scrollY;
  const scrolls=$$('#content .table-wrap,#content .vaults').map(node=>({left:node.scrollLeft,top:node.scrollTop}));
  renderDesktopPage();updateAvailability();
  $$('#content .table-wrap,#content .vaults').forEach((node,index)=>{if(scrolls[index]){node.scrollLeft=scrolls[index].left;node.scrollTop=scrolls[index].top;}});
  if(focus&&!active.isConnected){const node=$(focus.selector);if(node&&!node.disabled){node.focus({preventScroll:true});if(focus.start!==null&&focus.start!==undefined&&node.setSelectionRange)node.setSelectionRange(focus.start,focus.end,focus.direction||'none');}}
  if(window.scrollX!==scrollX||window.scrollY!==scrollY)window.scrollTo({left:scrollX,top:scrollY,behavior:'instant'});
};
if(sections[location.hash.slice(1)])state.section=location.hash.slice(1);
hydrate();render();host('refresh');setInterval(()=>{if(!document.hidden&&desktop.pending.size<2)host('refresh');},1000);
