using System;
using System.Collections;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace WinUp {
    partial class MainForm {
        sealed class DesktopAction {
            internal string Id, Section;
            internal Button Button;
            internal ToolStripItem Item;
            internal string Title { get { return Button != null ? Button.Text : Item.Text; } }
            internal bool Enabled { get { return Button != null ? Button.Enabled : Item.Enabled; } }
        }
        readonly Dictionary<string,DesktopAction> desktopActions = new Dictionary<string,DesktopAction>();
        readonly JavaScriptSerializer desktopJson = new JavaScriptSerializer { MaxJsonLength=8*1024*1024, RecursionLimit=64 };
        WebView2 desktopView;
        Label desktopDrop;
        bool desktopExecuting, desktopReady;
        string desktopSection="Пароли";
        string desktopTheme="dark";
        string[] desktopBrowsers;
        const string DesktopOrigin="https://winup.local/";

        void InitializeDesktopSurface() {
            desktopBrowsers=Browsers.Installed().Select(b=>b.Name).ToArray();
            foreach(TabPage page in tabs.TabPages) CollectDesktopControls(page,page.Text);
            if(MainMenuStrip!=null) foreach(ToolStripItem item in MainMenuStrip.Items) CollectDesktopMenu(item,"Меню");
            foreach(var list in new[]{pwList,otpList,passkeyList,instList,portList,linkList,wgList,fileItems}) { IntPtr handle=list.Handle; }
            try { using(var input=Assembly.GetExecutingAssembly().GetManifestResourceStream("desktop/icon.ico")) if(input!=null) Icon=new Icon(input); } catch { }
            try { string path=Path.Combine(Paths.Data,"desktop-theme.txt"); if(File.Exists(path)&&File.ReadAllText(path)=="light")desktopTheme="light"; } catch { }
            desktopView=new WebView2 {Dock=DockStyle.Fill,DefaultBackgroundColor=Color.FromArgb(16,19,27)};
            desktopView.AllowExternalDrop=false;
            foreach(Control control in Controls) control.Visible=false;
            Controls.Add(desktopView);desktopView.BringToFront();
            desktopDrop=new Label{Text="Перетащите файлы или папки сюда для добавления в открытое хранилище",Dock=DockStyle.Bottom,Height=42,TextAlign=ContentAlignment.MiddleCenter,AllowDrop=true,Visible=false,BackColor=Color.FromArgb(28,35,49),ForeColor=Color.FromArgb(157,173,199)};
            desktopDrop.DragEnter+=(s,e)=>{if(e.Data.GetDataPresent(DataFormats.FileDrop)&&fileVault!=null&&!fileVault.ReadOnly&&!fileBusy)e.Effect=DragDropEffects.Copy;};
            desktopDrop.DragDrop+=(s,e)=>{if(fileVault==null||fileVault.ReadOnly||fileBusy)return;try{ImportPaths((string[])e.Data.GetData(DataFormats.FileDrop));}catch(Exception ex){MessageBox.Show(this,ex.Message,"WinUp — файлы",MessageBoxButtons.OK,MessageBoxIcon.Warning);}};
            Controls.Add(desktopDrop);
            Size=new Size(Math.Min(1320,Screen.PrimaryScreen.WorkingArea.Width-40),Math.Min(880,Screen.PrimaryScreen.WorkingArea.Height-40));
            Shown+=async (sender,args)=>await StartDesktopSurface();
            FormClosed+=(sender,args)=>{desktopReady=false;if(desktopView!=null)desktopView.Dispose();};
        }
        void CollectDesktopControls(Control control,string section) {
            var button=control as Button;
            if(button!=null&&button.Text!="Ещё…") {
                string id="n"+desktopActions.Count;
                desktopActions.Add(id,new DesktopAction{Id=id,Section=section,Button=button});
            }
            if(control.ContextMenuStrip!=null) foreach(ToolStripItem item in control.ContextMenuStrip.Items) CollectDesktopMenu(item,section);
            foreach(Control child in control.Controls) CollectDesktopControls(child,section);
        }
        void CollectDesktopMenu(ToolStripItem item,string section) {
            var parent=item as ToolStripDropDownItem;
            if(parent!=null&&parent.DropDownItems.Count>0){foreach(ToolStripItem child in parent.DropDownItems)CollectDesktopMenu(child,section);return;}
            if(item is ToolStripSeparator||string.IsNullOrWhiteSpace(item.Text))return;
            string id="n"+desktopActions.Count;
            desktopActions.Add(id,new DesktopAction{Id=id,Section=section,Item=item});
        }
        async Task StartDesktopSurface() {
            try {
                var options=new CoreWebView2EnvironmentOptions();
                var environment=await CoreWebView2Environment.CreateAsync(null,Path.Combine(Paths.Data,"webview-profile"),options);
                await desktopView.EnsureCoreWebView2Async(environment);
                var core=desktopView.CoreWebView2;
                core.Settings.AreDevToolsEnabled=false;
                core.Settings.AreDefaultContextMenusEnabled=false;
                core.Settings.IsStatusBarEnabled=false;
                core.Settings.AreHostObjectsAllowed=false;
                core.Settings.IsPasswordAutosaveEnabled=false;
                core.Settings.IsGeneralAutofillEnabled=false;
                core.Settings.AreBrowserAcceleratorKeysEnabled=false;
                core.PermissionRequested+=(s,e)=>e.State=CoreWebView2PermissionState.Deny;
                core.NewWindowRequested+=(s,e)=>e.Handled=true;
                core.DownloadStarting+=(s,e)=>e.Cancel=true;
                core.NavigationStarting+=(s,e)=>{Uri uri;if(!Uri.TryCreate(e.Uri,UriKind.Absolute,out uri)||uri.GetLeftPart(UriPartial.Path)!=DesktopOrigin+"index.html")e.Cancel=true;};
                core.AddWebResourceRequestedFilter("*",CoreWebView2WebResourceContext.All);
                core.WebResourceRequested+=(s,e)=>ServeDesktopResource(core,e);
                core.WebMessageReceived+=DesktopMessage;
                core.ProcessFailed+=(s,e)=>DesktopFallback("Новый интерфейс остановлен. WinUp перешёл к обычному интерфейсу. Для нового оформления перезапустите программу.");
                core.Navigate(DesktopOrigin+"index.html");
                desktopReady=true;
            } catch(Exception ex) {
                DesktopFallback("Не удалось открыть новый интерфейс: "+ex.Message+". WinUp работает в обычном интерфейсе. Для нового оформления нужен Microsoft Edge WebView2 Runtime.");
            }
        }
        static void ServeDesktopResource(CoreWebView2 core,CoreWebView2WebResourceRequestedEventArgs args) {
            Uri uri;string name=null;
            if(Uri.TryCreate(args.Request.Uri,UriKind.Absolute,out uri)&&uri.Scheme=="https"&&uri.Host=="winup.local"&&uri.IsDefaultPort&&string.IsNullOrEmpty(uri.Query)) {
                string candidate=uri.AbsolutePath.TrimStart('/');
                if(new[]{"index.html","style.css","app.js","desktop.js","icon.svg"}.Contains(candidate))name=candidate;
            }
            var stream=name==null?null:Assembly.GetExecutingAssembly().GetManifestResourceStream("desktop/"+name);
            if(stream==null){args.Response=core.Environment.CreateWebResourceResponse(new MemoryStream(),403,"Forbidden","Content-Type: text/plain\r\nCache-Control: no-store");return;}
            string type=name.EndsWith(".html")?"text/html; charset=utf-8":name.EndsWith(".css")?"text/css; charset=utf-8":name.EndsWith(".svg")?"image/svg+xml":"text/javascript; charset=utf-8";
            string policy="default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'";
            args.Response=core.Environment.CreateWebResourceResponse(stream,200,"OK","Content-Type: "+type+"\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: "+policy);
        }
        static bool TrustedDesktopSource(string source) {
            Uri uri;return Uri.TryCreate(source,UriKind.Absolute,out uri)&&uri.GetLeftPart(UriPartial.Path)==DesktopOrigin+"index.html"&&string.IsNullOrEmpty(uri.Query)&&string.IsNullOrEmpty(uri.UserInfo);
        }
        static string DesktopValue(Dictionary<string,object> request,string name) {object value;return request.TryGetValue(name,out value)&&value is string?(string)value:"";}
        static string[] DesktopValues(Dictionary<string,object> request,string name) {object value;if(!request.TryGetValue(name,out value)||value is string)return new string[0];var list=value as IEnumerable;return list==null?new string[0]:list.Cast<object>().OfType<string>().Take(10000).ToArray();}
        async void DesktopMessage(object sender,CoreWebView2WebMessageReceivedEventArgs args) {
            if(!desktopReady||!TrustedDesktopSource(args.Source))return;
            string requestId="";
            try {
                string json=args.WebMessageAsJson;if(json.Length>65536)throw new IOException("Слишком большой запрос интерфейса.");
                var request=desktopJson.Deserialize<Dictionary<string,object>>(json);requestId=DesktopValue(request,"requestId");
                if(requestId.Length>80)throw new IOException("Неверный идентификатор запроса.");
                string command=DesktopValue(request,"command");
                if(command=="refresh"){string active=DesktopValue(request,"section");if(tabs.TabPages.Cast<TabPage>().Any(p=>p.Text==active))desktopSection=active;if(!desktopExecuting)DesktopSelect(request);DesktopReply(requestId,null);return;}
                DesktopAction requestedAction;
                bool cancel=command=="native"&&desktopActions.TryGetValue(DesktopValue(request,"actionId"),out requestedAction)&&requestedAction.Title.StartsWith("Отмен",StringComparison.Ordinal);
                if((desktopExecuting||fileBusy||wgBusy||busyLogin||unlockBusy||installAuthorizing||appOperations>0)&&command!="lock-all"&&command!="lock-secrets"&&!cancel)throw new IOException("Дождитесь завершения операции или отмените её в открытом окне.");
                bool wasExecuting=desktopExecuting;
                desktopExecuting=true;
                try {
                    string section=DesktopValue(request,"section");
                    if(tabs.TabPages.Cast<TabPage>().Any(p=>p.Text==section)){desktopSection=section;SelectTab(section);}
                    DesktopSelect(request);
                    if(command=="native") {
                        DesktopAction action;
                        if(!desktopActions.TryGetValue(DesktopValue(request,"actionId"),out action))throw new IOException("Команда не относится к интерфейсу WinUp.");
                        if(!action.Enabled)throw new IOException("Это действие сейчас недоступно.");
                        if(action.Section!="Меню"){desktopSection=action.Section;SelectTab(action.Section);}
                        var pending=DesktopNativeTask(action);
                        if(pending!=null)await pending;
                        else if(action.Button!=null)typeof(Button).GetMethod("OnClick",BindingFlags.Instance|BindingFlags.NonPublic).Invoke(action.Button,new object[]{EventArgs.Empty});
                        else action.Item.PerformClick();
                    } else if(command=="unlock") Unlock();
                    else if(command=="lock-secrets")LockVaultCore(true);
                    else if(command=="lock-all")LockVault();
                    else if(command=="file-select"){
                        string folder=DesktopValue(request,"folder");if(!fileCatalog.Items.Contains(folder))throw new IOException("Хранилище отсутствует в списке.");fileCatalog.SelectedItem=folder;
                    } else if(command=="file-open-item")OpenFileItem();
                    else if(command=="login")await LoginSelected();
                    else if(command=="login-checked")await LoginChecked();
                    else if(command=="copy-login")CopyField(true);
                    else if(command=="copy-password")CopyField(false);
                    else if(command=="copy-otp")CopyOtp();
                    else if(command=="copy-account-otp")CopyTotp();
                    else if(command=="reveal")DesktopReveal(requestId);
                    else if(command=="copy-metadata")SecureClip.Copy(DesktopValue(request,"text"));
                    else if(command=="winget-search"){wgQuery.Text=DesktopValue(request,"query");await WgSearch();}
                    else if(command=="winget-mode"){string mode=DesktopValue(request,"mode");if(mode=="set")await WgShowSet();else if(mode=="updates")await WgUpgrades();else{wgQuery.Text=DesktopValue(request,"query");await WgSearch();}}
                    else if(command=="settings")DesktopSaveSettings(request);
                    else if(command=="theme") {string theme=DesktopValue(request,"theme");if(theme!="light"&&theme!="dark")throw new IOException("Неверная тема.");Paths.AtomicWrite(Path.Combine(Paths.Data,"desktop-theme.txt"),Encoding.UTF8.GetBytes(theme));desktopTheme=theme;Appearance.SetTheme(theme=="dark");}
                    else throw new IOException("Неизвестная команда интерфейса.");
                } finally {desktopExecuting=wasExecuting;}
                DesktopReply(requestId,null);
            } catch(Exception ex) {var inner=ex is TargetInvocationException&&ex.InnerException!=null?ex.InnerException:ex;DesktopReply(requestId,inner.Message);}
        }
        Task DesktopNativeTask(DesktopAction action) {
            // Async event handlers return before their operation completes. Dispatch the
            // same tasks directly so the bridge holds its selection until completion.
            string title=action.Title;
            if(action.Section=="Пароли") {
                if(title=="Войти")return LoginSelected();
                if(title=="Войти в отмеченные")return LoginChecked();
            } else if(action.Section=="WinGet") {
                if(title=="Найти")return WgSearch();
                if(title=="Проверить обновления")return WgUpgrades();
                if(title=="Мой набор")return WgShowSet();
            } else if(action.Section=="Запуск"&&title=="Добавить файлы...")return AddFilesDialog("portable");
            else if(action.Section=="Установка") {
                if(title=="Добавить файлы...")return AddFilesDialog("install");
                if(title=="Добавить папку...")return AddFolderDialog();
                if(title=="Найти новые в apps")return ScanNew(false);
                if(title=="Найти установщики на ПК...")return FindInstallers();
                if(title=="Установить отмеченные")return InstallChecked();
            } else if(action.Section=="Меню") {
                if(title=="Мастер первого запуска...")return RunWizard();
                if(title=="Найти установщики на ПК...")return FindInstallers();
            }
            return null;
        }
        void DesktopSelect(Dictionary<string,object> request) {
            string selected=DesktopValue(request,"selected"),otp=DesktopValue(request,"otp"),key=DesktopValue(request,"key"),app=DesktopValue(request,"app"),link=DesktopValue(request,"link");
            var checkedIds=new HashSet<string>(DesktopValues(request,"checked"));
            foreach(var list in new[]{pwList,otpList,passkeyList,instList,portList,linkList,wgList})foreach(ListViewItem item in list.Items){
                string id="";var entry=item.Tag as LoginEntry;var code=item.Tag as OtpEntry;var program=item.Tag as AppItem;var address=item.Tag as LinkItem;var package=item.Tag as WingetRow;
                if(entry!=null)id=entry.Id;else if(code!=null)id=code.Id;else if(program!=null)id=program.Id;else if(address!=null)id=address.Id;else if(package!=null)id=package.Id;
                item.Selected=list==pwList?id==selected:list==otpList?id==otp:list==passkeyList?id==key:list==portList||list==instList?id==app:list==linkList?id==link:checkedIds.Contains(id);
                if(list.CheckBoxes)item.Checked=checkedIds.Contains(id);
            }
            var files=new HashSet<string>(DesktopValues(request,"files"));foreach(ListViewItem item in fileItems.Items)item.Selected=files.Contains(item.Text);
            silentBox.Checked=!request.ContainsKey("silent")||!(request["silent"] is bool)||(bool)request["silent"];wgSilent.Checked=silentBox.Checked;
        }
        void DesktopSaveSettings(Dictionary<string,object> request) {
            object raw;int minutes=store.Settings.AutoLockMinutes;
            if(request.TryGetValue("minutes",out raw)&&(!int.TryParse(Convert.ToString(raw),out minutes)||minutes<1||minutes>1440))throw new IOException("Время блокировки: 1–1440 минут.");
            bool traySetting=request.TryGetValue("tray",out raw)&&raw is bool?(bool)raw:store.Settings.MinimizeToTray;
            bool notify=request.TryGetValue("notify",out raw)&&raw is bool?(bool)raw:store.Settings.FillNotify;
            string browser=request.ContainsKey("browser")?DesktopValue(request,"browser"):store.Settings.Browser;
            if(browser!=""&&Browsers.Find(browser)==null)throw new IOException("Выбранный браузер не установлен.");
            int oldMinutes=store.Settings.AutoLockMinutes;bool oldTray=store.Settings.MinimizeToTray,oldNotify=store.Settings.FillNotify;string oldBrowser=store.Settings.Browser;
            store.Settings.AutoLockMinutes=minutes;store.Settings.MinimizeToTray=traySetting;store.Settings.FillNotify=notify;store.Settings.Browser=browser;
            try {store.Save();}
            catch(Exception ex) {store.Settings.AutoLockMinutes=oldMinutes;store.Settings.MinimizeToTray=oldTray;store.Settings.FillNotify=oldNotify;store.Settings.Browser=oldBrowser;throw new IOException("Не удалось сохранить настройки: "+ex.Message,ex);}
            FillNotifyEnabled=notify;
            if(notify!=oldNotify)PwLog(notify?"Расширение: уведомление о каждой вставке пароля включено.":"Расширение: уведомление о вставке пароля выключено.");
            SetStatus("Настройки сохранены.");
        }
        void DesktopReveal(string requestId) {
            var entry=SelectedEntry();if(vault==null||entry==null)throw new IOException("Сначала откройте базу и выберите аккаунт.");
            entry.UsePassword(password=>{DesktopPost(new{type="secret",requestId=requestId,id=entry.Id,value=password});return 0;});
        }
        void DesktopFallback(string reason){
            desktopReady=false;
            if(IsDisposed)return;
            if(desktopView!=null)desktopView.Visible=false;
            if(desktopDrop!=null)desktopDrop.Visible=false;
            LockVaultCore(true);
            tabs.Visible=true;status.Visible=true;if(MainMenuStrip!=null)MainMenuStrip.Visible=true;
            SetStatus(reason);
        }
        void DesktopPost(object value) {if(desktopReady&&desktopView!=null&&desktopView.CoreWebView2!=null&&!IsDisposed)try{desktopView.CoreWebView2.PostWebMessageAsJson(desktopJson.Serialize(value));}catch(Exception){DesktopFallback("Не удалось обновить новый интерфейс. База закрыта; WinUp работает в обычном интерфейсе.");}}
        void DesktopReply(string requestId,string error) {if(!desktopReady)return;desktopDrop.Visible=desktopSection=="Файлы"&&fileVault!=null&&fileVault.Open&&!fileVault.ReadOnly&&!fileBusy;DesktopPost(new{type="state",requestId=requestId,error=error,data=DesktopSnapshot()});}
        internal object DesktopSnapshot() {
            var groups=vault==null?new List<AccountGroupInfo>():vault.AccountGroups();
            var entries=vault==null?new List<LoginEntry>():vault.Entries;
            var otp=vault==null?new List<OtpEntry>():vault.Otp;
            var accounts=entries.Where(e=>e.Kind!="passkey").Select(e=>new{id=e.Id,name=e.Name,type=e.Kind,url=e.Target??"",loginUrl=e.LoginUrl??"",login=AccountOrganization.DisplayLogin(e),extraLogin=AccountOrganization.DisplayLogin(e,true),password="",category=AccountOrganization.Category(e,store.Templates),group=groups.Where(g=>g.Id==e.GroupId).Select(g=>g.Path).FirstOrDefault()??"",tags=e.Tags,otp=e.TwoFa=="link"&&otp.Any(o=>o.Id==e.OtpId)?e.OtpId:"",passkey=e.PasskeyId??"",browser=e.Browser??"",pinned=e.Pinned,note=e.Notes??"",app=e.AppTarget??"",args=e.Args??"",window=e.Window??"",delay=e.Delay,twoFa=e.TwoFa,autoEnter=e.AutoEnter,fields=new object[0],attachments=new object[0],history=new object[0],recovery=""}).ToArray();
            var codes=otp.Select(o=>{string code="";try{code=Totp.Code(o);}catch(FormatException){}return new{id=o.Id,name=o.Issuer,login=o.Account,note=o.Notes,period=o.Period,digits=o.Digits,algorithm=o.Algorithm,code=code,left=Totp.SecondsLeftFor(o.Period)};}).ToArray();
            var keys=entries.Where(e=>e.Kind=="passkey").Select(e=>new{id=e.Id,name=e.Name,rp=e.Target,login=e.Login,method="WinUp",created="",history=new object[0]}).ToArray();
            var apps=store.Apps.Where(a=>a.Kind=="portable").Select(a=>new{id=a.Id,name=a.Name,path=a.File,args=a.Args,description=a.Description,note=a.Note,admin=a.Admin,exists=a.Exists,symbol="laptop",category="Программа"}).ToArray();
            var installers=store.Apps.Where(a=>a.Kind=="install").Select(a=>new{id=a.Id,name=a.Name,path=a.File,file=Path.GetFileName(a.File),args=a.Args,type="Установщик",description=a.Description,note=a.Note,admin=a.Admin,status=a.Exists?"Готов к установке":"Файл не найден"}).ToArray();
            var packages=wgList.Items.Cast<ListViewItem>().Select(item=>new{id=((WingetRow)item.Tag).Id,name=item.Text,version=item.SubItems[2].Text,available=item.SubItems[3].Text,status=item.SubItems[4].Text,symbol="box",set=store.Winget.Any(p=>string.Equals(p.Id,((WingetRow)item.Tag).Id,StringComparison.OrdinalIgnoreCase)),installed=wgView=="upgrade"||wgView=="set"&&!string.IsNullOrEmpty(((WingetRow)item.Tag).Version)}).ToArray();
            string selectedFolder=fileCatalog.SelectedItem as string;
            var fileVaults=fileCatalog.Items.Cast<string>().Select(folder=>new{id=folder,path=folder,name=Path.GetFileName(folder),locked=fileVault==null||!fileVault.Open||fileVault.Folder!=folder,drive=fileVault!=null&&fileVault.Open&&fileVault.Folder==folder?(fileVault.MountPoint??""):"",@readonly=fileVault!=null&&fileVault.Folder==folder&&fileVault.ReadOnly,history=filePreferences.History,projectMode=filePreferences.ProjectMode}).ToArray();
            var files=fileVault==null||!fileVault.Open?new object[0]:fileItems.Items.Cast<ListViewItem>().Select(item=>(object)new{id=item.Text,name=item.Text,parent=fileDirectory,vault=fileVault.Folder,folder=item.Tag is bool&&(bool)item.Tag,size=item.SubItems[1].Text}).ToArray();
            var selection=new{passwords=SelectedEntry()==null?"":SelectedEntry().Id,otp=SelectedOtp()==null?"":SelectedOtp().Id,passkeys=passkeyList.SelectedItems.Count==0?"":((LoginEntry)passkeyList.SelectedItems[0].Tag).Id,run=portList.SelectedItems.Count==0?"":((AppItem)portList.SelectedItems[0].Tag).Id,install=instList.SelectedItems.Count==0?"":((AppItem)instList.SelectedItems[0].Tag).Id,download=SelectedLink()==null?"":SelectedLink().Id,checkedPasswords=pwList.CheckedItems.Cast<ListViewItem>().Select(item=>((LoginEntry)item.Tag).Id).ToArray(),checkedInstallers=instList.CheckedItems.Cast<ListViewItem>().Select(item=>((AppItem)item.Tag).Id).ToArray(),checkedPackages=wgList.CheckedItems.Cast<ListViewItem>().Select(item=>((WingetRow)item.Tag).Id).ToArray(),files=fileItems.SelectedItems.Cast<ListViewItem>().Select(item=>item.Text).ToArray()};
            return new{locked=vault==null,baseExists=BaseExists(),database=Path.GetFileName(Paths.KdbxFile),accounts=accounts,otps=codes,passkeys=keys,groups=groups.Select(g=>g.Path).ToArray(),apps=apps,installers=installers,packages=packages,wingetMode=wgView=="upgrade"?"updates":wgView=="set"?"set":"all",links=store.Links.Select(l=>new{id=l.Id,name=l.Name,url=l.Url,description=l.Description}).ToArray(),vaults=fileVaults,files=files,fileVault=selectedFolder,path=fileDirectory,fileState=fileState.Text,status=status.Text,activity=pwLog.Lines.Take(200).ToArray(),browser=store.Settings.Browser,browsers=desktopBrowsers,extensionConnected=DesktopDependencies.OwnBrowserConnection(),theme=desktopTheme,busy=desktopExecuting||fileBusy||wgBusy||busyLogin||unlockBusy||installAuthorizing||appOperations>0,selection=selection,settings=new{tray=store.Settings.MinimizeToTray,autoLock=store.Settings.AutoLockMinutes,notify=store.Settings.FillNotify,backupFolder=store.Settings.BackupDir,backupKeep=store.Settings.BackupKeep},actions=desktopActions.Values.Select(a=>new{id=a.Id,section=a.Section,title=a.Title,enabled=a.Enabled,check=a.Item is ToolStripMenuItem?((ToolStripMenuItem)a.Item).Checked:false}).ToArray()};
        }
    }
}
