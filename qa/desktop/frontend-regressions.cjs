// Browser-only regression checks. The native bridge is synthetic; no real actions execute.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {chromium}=require('playwright');
const account={id:'account1',name:'Учебный аккаунт',type:'site',url:'https://example.invalid',loginUrl:'',login:'qa@example.invalid',extraLogin:'',password:'',category:'Учебная',group:'',tags:[],otp:'',passkey:'',browser:'',pinned:false,note:'',app:'',fields:[],attachments:[],history:[]};
const snapshot={locked:false,baseExists:true,database:'qa-only.kdbx',browser:'',browsers:[],accounts:[account],otps:[],passkeys:[],apps:[{id:'app1',name:'Alpha',path:'alpha.exe',description:'',exists:true},{id:'app2',name:'Beta',path:'beta.exe',description:'',exists:false}],installers:[{id:'install1',name:'Alpha',file:'alpha.exe',args:'',type:'Установщик',status:'Готов к установке'},{id:'install2',name:'Beta',file:'beta.exe',args:'',type:'Установщик',status:'Готов к установке'}],packages:[{id:'package1',name:'Alpha',version:'',available:'1',status:'',set:false,installed:false},{id:'package2',name:'Beta',version:'',available:'1',status:'',set:false,installed:false}],links:[],vaults:[],files:[],fileVault:null,path:'',groups:[],busy:false,settings:{autoLock:10,tray:false,notify:false},activity:[],theme:'dark',extensionConnected:false,status:'Учебные данные',fileState:'',actions:[{id:'edit-account',section:'Пароли',title:'Изменить...',enabled:true},{id:'edit-installer',section:'Установка',title:'Изменить...',enabled:true},{id:'remove-installer',section:'Установка',title:'Убрать из списка',enabled:true},{id:'launch-app',section:'Запуск',title:'Запустить',enabled:true},{id:'edit-app',section:'Запуск',title:'Изменить...',enabled:true},{id:'remove-app',section:'Запуск',title:'Убрать из списка',enabled:true},{id:'about',section:'Меню',title:'О программе',enabled:true},{id:'backup',section:'Меню',title:'Архив для переноса на другой ПК...',enabled:true}],selection:{passwords:'account1',run:'app1',install:'install1',otp:'',passkeys:'',download:'',checkedPasswords:[],checkedInstallers:[],checkedPackages:[],files:[]}};
(async()=>{
  const browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
  try{
    const page=await browser.newPage({viewport:{width:1040,height:680}}),errors=[];
    page.on('pageerror',error=>errors.push(error.message));
    await page.addInitScript(data=>{
      window.qaSnapshot=data;window.qaRequests=[];window.qaListeners=[];
      window.qaReply=message=>window.qaListeners.forEach(listener=>listener({data:message}));
      window.chrome=window.chrome||{};
      window.chrome.webview={addEventListener:(type,listener)=>window.qaListeners.push(listener),postMessage:request=>{window.qaRequests.push(request);if(request.command==='refresh')setTimeout(()=>window.qaReply({type:'state',requestId:request.requestId,data:window.qaSnapshot}),0);}};
    },snapshot);
    await page.goto('file:///'+path.resolve(__dirname,'../../src/desktop/index.html').replace(/\\/g,'/'));
    await page.waitForFunction(()=>desktop.ready);
    assert.deepEqual(await page.evaluate(()=>{navigate('install');state.query='Alpha';render();A['installer-select-all']();return [...state.checked];}),['install1']);
    assert.deepEqual(await page.evaluate(()=>{navigate('winget');state.query='Alpha';render();A['wg-select-all']();return [...state.checked];}),['package1']);
    assert.deepEqual(await page.evaluate(()=>{navigate('passwords');const input=document.querySelector('#search');input.value='account';state.query='account';input.focus();input.setSelectionRange(1,5,'backward');qaSnapshot={...qaSnapshot,accounts:qaSnapshot.accounts.map(account=>({...account,note:'Changed snapshot'}))};applyNative(qaSnapshot);return [document.activeElement.id,document.activeElement.selectionStart,document.activeElement.selectionEnd,document.activeElement.selectionDirection];}),['search',1,5,'backward']);
    await page.evaluate(()=>desktopCommands());
    assert.ok(await page.locator('#native-results .command-group').count()>1);
    await page.locator('#native-search').fill('несуществующая команда');
    assert.equal(await page.locator('#native-results .command-row').count(),0);
    assert.match(await page.locator('#native-results .no-results').innerText(),/не найдено/);
    await page.locator('#native-search').fill('о программе');
    await page.evaluate(()=>{window.qaNativeCount=0;window.qaOriginalNative=A.native;A.native=()=>qaNativeCount++;document.querySelector('#native-search').dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowDown',bubbles:true}));document.activeElement.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));A.native=qaOriginalNative;});
    assert.equal(await page.evaluate(()=>qaNativeCount),1);
    assert.equal(await page.evaluate(()=>document.activeElement.dataset.native),'about');
    assert.deepEqual(await page.evaluate(()=>{closeModal();navigate('run');desktop.selection.run='app1';render();const row=document.querySelector('[data-id="app2"][data-action="select-item"]'),child=document.createElement('button');child.disabled=true;child.dataset.action='app-launch';child.innerHTML='<span>Disabled child</span>';row.append(child);child.firstChild.dispatchEvent(new MouseEvent('click',{bubbles:true}));return [desktop.selection.run,!!document.querySelector('#selection-actions [data-native="remove-app"]')];}),['app1',true]);
    assert.deepEqual(await page.evaluate(()=>{navigate('winget');state.query='synthetic search';render();document.querySelector('#search').dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));const request=qaRequests.at(-1);qaReply({type:'state',requestId:request.requestId,data:qaSnapshot});return [request.command,request.query];}),['winget-search','synthetic search']);
    assert.deepEqual(await page.evaluate(()=>{A.settings();const input=document.querySelector('[name="minutes"]');input.value='0';const count=qaRequests.length;A['modal-submit']();return [document.querySelector('#modal').open,qaRequests.length===count,input.value];}),[true,true,'0']);
    assert.deepEqual(await page.evaluate(()=>{const input=document.querySelector('[name="minutes"]');input.value='17';A['modal-submit']();const request=qaRequests.at(-1);qaReply({type:'state',requestId:request.requestId,error:'Synthetic settings failure',data:qaSnapshot});return [document.querySelector('#modal').open,input.isConnected,input.value,document.querySelector('.inline-error').textContent];}),[true,true,'17','Synthetic settings failure']);
    assert.equal(await page.evaluate(()=>{A['modal-submit']();const request=qaRequests.at(-1);qaReply({type:'state',requestId:request.requestId,data:{...qaSnapshot,settings:{...qaSnapshot.settings,autoLock:17}}});return document.querySelector('#modal').open;}),false);
    assert.deepEqual(await page.evaluate(()=>{navigate('install');state.query='';render();const requestId=host('native',{section:'Установка',actionId:'edit-installer'});qaReply({type:'state',requestId,data:{...qaSnapshot,selection:{...qaSnapshot.selection,install:'install2',checkedInstallers:['install2']}}});return [desktop.selection.install,[...state.checked]];}),['install2',['install2']]);
    await page.addStyleTag({content:fs.readFileSync(path.resolve(__dirname,'../../src/desktop-fixes.css'),'utf8')});
    const fileScroll=await page.evaluate(()=>{
      qaSnapshot={...qaSnapshot,vaults:[{id:'qa-vault',name:'Учебное хранилище',path:'qa-only',drive:'',locked:false,readonly:false}],fileVault:'qa-vault',files:Array.from({length:90},(_,index)=>({id:'qa-file-'+index,name:'Учебный файл '+index,folder:false,size:'1 КБ'}))};applyNative(qaSnapshot);navigate('files');
      const last=document.querySelectorAll('[data-file-check]')[89];last.scrollIntoView({block:'end'});const before=scrollY;last.checked=true;last.dispatchEvent(new Event('change',{bubbles:true}));document.documentElement.style.setProperty('--dock-height',document.querySelector('.action-dock').offsetHeight+'px');
      const dock=document.querySelector('.action-dock').getBoundingClientRect(),vault=document.querySelector('.vaults').getBoundingClientRect();return {before,after:scrollY,delta:scrollY-before,dockTop:dock.top,dockBottom:dock.bottom,vaultTop:vault.top,vaultGap:vault.top-dock.bottom,export:!!document.querySelector('#selection-actions [data-action=file-export]'),delete:!!document.querySelector('#selection-actions [data-action=file-delete]'),selected:payload().files.includes('qa-file-89')};
    });
    console.log('File scroll diagnostic:',JSON.stringify(fileScroll));
    assert.ok(Math.abs(fileScroll.delta)<3&&fileScroll.dockTop>=-1&&fileScroll.dockTop<2&&fileScroll.vaultGap>=10&&fileScroll.vaultGap<15&&fileScroll.export&&fileScroll.delete&&fileScroll.selected,'Last file selection preserves scroll position and sticky controls');
    await page.screenshot({path:path.resolve(__dirname,'screens/frontend-file-scroll.png')});
    for(const theme of ['dark','light']){
      await page.evaluate(theme=>{document.documentElement.dataset.theme=theme;desktopCommands();},theme);
      for(const viewport of [{width:1280,height:800},{width:900,height:600},{width:620,height:380},{width:420,height:300}]){
        await page.setViewportSize(viewport);
        assert.equal(await page.evaluate(()=>{const dialog=document.querySelector('#modal').getBoundingClientRect(),footer=document.querySelector('#modal-footer').getBoundingClientRect();return dialog.top>=-1&&dialog.bottom<=innerHeight+1&&footer.bottom<=innerHeight+1&&document.documentElement.scrollWidth<=innerWidth;}),true,`${theme} command dialog fits ${viewport.width}x${viewport.height}`);
      }
      assert.equal(await page.evaluate(()=>{const button=document.createElement('button');button.className='button primary';button.disabled=true;button.textContent='Disabled';document.querySelector('#modal-body').append(button);const style=getComputedStyle(button),luminance=color=>color.match(/[\d.]+/g).slice(0,3).map(Number).map(channel=>channel/255).map(channel=>channel<=.04045?channel/12.92:((channel+.055)/1.055)**2.4).reduce((sum,channel,index)=>sum+channel*[.2126,.7152,.0722][index],0),foreground=luminance(style.color),background=luminance(style.backgroundColor),contrast=(Math.max(foreground,background)+.05)/(Math.min(foreground,background)+.05),readable=contrast>=4.5&&style.opacity==='1';button.remove();return readable;}),true,`${theme} disabled primary meets 4.5:1 contrast`);
    }
    assert.deepEqual(errors,[]);
    console.log('PASS: 12 browser regressions and 10 layout/theme checks, no native operations, no JavaScript errors.');
  }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
