using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using KeePassLib;

namespace WinUp {
    static partial class SecurityHarness {
        static void CorrectionsTests() {
            LocalApplicationTests();
            const string token="corrections-synthetic-token";
            const string codes="SYNTHETIC-RECOVERY-01\r\nSYNTHETIC-RECOVERY-02";
            Ui(delegate {
                NewVault(false); BrowserPair.Save(token,"Synthetic corrections test");
                var tabs=(TabControl)typeof(MainForm).GetField("tabs",Private).GetValue(form);
                Check("requested-tab-order",string.Join("|",tabs.TabPages.Cast<TabPage>().Select(t=>t.Text))=="Пароли|2FA|Ключи доступа|Файлы|Запуск|WinGet|Установка|Скачать","actual MainForm tabs");
                var e=form.VaultNow.Entries[0]; e.Kind="both"; e.Login2="sandbox@example.com"; e.AppTarget="%WINDIR%\\notepad.exe"; e.RecoveryCodes=codes;e.LoginUrl="https://example.com/login";
                using(var dialog=new EntryDialog(e.Copy(),new AppStore(),false,form.VaultNow.Otp,form.VaultNow.Entries)) {
                    var pw=(TextBox)typeof(EntryDialog).GetField("pass",Private).GetValue(dialog);
                    var alt=(TextBox)typeof(EntryDialog).GetField("login2",Private).GetValue(dialog);
                    Check("account-editor-secret-and-secondary-login",pw.UseSystemPasswordChar && pw.Text=="Audit-only-secret!" && alt.Text=="sandbox@example.com","native input fields preserve protected source");
                    dialog.Show(form);Application.DoEvents();
                    var ok=(Button)typeof(Dlg).GetField("Ok",Private).GetValue(dialog);
                    Check("account-editor-save-button-visible-with-long-form",ok.Visible && dialog.ClientRectangle.Contains(dialog.PointToClient(ok.PointToScreen(System.Drawing.Point.Empty))),"fixed bottom buttons");
                    using(var bitmap=new System.Drawing.Bitmap(dialog.Width,dialog.Height)){dialog.DrawToBitmap(bitmap,new System.Drawing.Rectangle(System.Drawing.Point.Empty,dialog.Size));bitmap.Save(@"C:\WinUp\test\corrections\entry-editor-ui.png");}
                    dialog.Close();
                }
                form.VaultNow.Save();
                var templates=new AppStore { Templates=Defaults.Load().Templates };
                using(var dialog=new EntryDialog(new LoginEntry(),templates,true,form.VaultNow.Otp,form.VaultNow.Entries)) {
                    var search=(TextBox)typeof(EntryDialog).GetField("templateFilter",Private).GetValue(dialog);
                    var box=(ComboBox)typeof(EntryDialog).GetField("tpl",Private).GetValue(dialog);
                    var kind=(ComboBox)typeof(EntryDialog).GetField("templateKind",Private).GetValue(dialog);
                    search.Text="Steam Community";
                    Check("template-search-reduces-list",box.Items.Count==2,"one matching service plus empty selection");
                    kind.SelectedIndex=1;
                    Check("template-type-filter-combines-with-search",box.Items.Count==1,"both-kind is excluded by site-only filter");
                }
                var db=(PwDatabase)typeof(KdbxStore).GetField("db",Private).GetValue(form.VaultNow);
                var stored=db.RootGroup.GetEntries(true).First(e2=>e2.Strings.ReadSafe(PwDefs.TitleField)=="Synthetic");
                Check("recovery-codes-protected-kdbx-field",stored.Strings.Get("WinUp.RecoveryCodes").IsProtected,"inner protected stream and encrypted database");
            });
            int left; StoreResult status;
            var reopened=KdbxStore.Open(Password,null,out left,out status);
            var restored=reopened.Entries.First(x=>x.Name=="Synthetic");
            Check("new-account-fields-survive-reopen",restored.Kind=="both" && restored.Login2=="sandbox@example.com" && restored.AppTarget=="%WINDIR%\\notepad.exe" && restored.LoginUrl=="https://example.com/login" && restored.UseRecoveryCodes(c=>c==codes),"KDBX save/reopen");
            var detached=restored.Copy(); reopened.Lock();
            Check("lock-erases-recovery-codes",restored.UseRecoveryCodes(c=>string.IsNullOrEmpty(c)) && detached.UseRecoveryCodes(c=>c==codes),"independent protected copy and lock erasure"); detached.ClearSecrets();
            var list=Request(new {type="list",token=token,url="https://example.com/"});
            Check("both-kind-available-in-extension",(bool)list["ok"] && ((ArrayList)list["items"]).Count==1,"application/site entries are available");
            string savedId=(string)((Dictionary<string,object>)((ArrayList)list["items"])[0])["id"];
            var fill=Request(new {type="fill",token=token,url="https://example.com/",id=savedId});
            Check("fill-secondary-login-without-recovery-leak",(bool)fill["ok"] && (string)fill["login2"]=="sandbox@example.com" && !fill.ContainsKey("recoveryCodes") && !fill.ContainsKey("passkey"),"secret recovery material stays native; ok="+fill["ok"]+"; error="+(fill.ContainsKey("error")?fill["error"]:"")+"; secondary="+(fill.ContainsKey("login2")?fill["login2"]:"missing"));
            var insecure=Request(new {type="save",token=token,url="http://example.com/",login="new-user",password="Synthetic-New-Password!"});
            Check("save-rejects-http",!(bool)insecure["ok"] && (string)insecure["error"]=="insecure","no native save on unprotected origin");
            var framed=Request(new {type="save",token=token,url="https://example.com/",login="new-user",password="Synthetic-New-Password!",framed=true});
            Check("save-rejects-child-frame",!(bool)framed["ok"] && (string)framed["error"]=="bad_request","top frame only");
            var unknown=Request(new {type="save",token="unpaired",url="https://example.com/",login="new-user",password="Synthetic-New-Password!"});
            Check("save-rejects-unpaired",!(bool)unknown["ok"] && (string)unknown["error"]=="not_paired","pairing is required");
            var oversized=Request(new {type="save",token=token,url="https://example.com/",login="new-user",password=new string('X',4097)});
            Check("save-rejects-oversized-password",!(bool)oversized["ok"] && (string)oversized["error"]=="bad_request","bounded request");
            Timer review=null; var seen=new HashSet<Form>(); int prompts=0; string action="approve";
            Ui(delegate {
                review=new Timer {Interval=50}; review.Tick+=delegate {
                    foreach(var dialog in Application.OpenForms.Cast<Form>().OfType<EntryDialog>().ToArray()) {
                        if(!seen.Add(dialog)) continue; prompts++;
                        if(action=="lock") { Lock(); continue; }
                        ((Button)typeof(Dlg).GetField(action=="cancel" ? "Cancel" : "Ok",Private).GetValue(dialog)).PerformClick();
                    }
                }; review.Start();
            });
            try {
                var saved=Request(new {type="save",token=token,url="https://example.com/login",login="new-user",password="Synthetic-New-Password!"});
                Check("save-requires-native-review",(bool)saved["ok"] && prompts==1 && !saved.ContainsKey("password"),"actual native dialog approved in lab");
                var updated=Request(new {type="save",token=token,url="https://example.com/login",login="new-user",password="Synthetic-Updated-Password!"});
                bool unique=false; Ui(delegate { unique=form.VaultNow.Entries.Count(e=>e.Login=="new-user")==1 && form.VaultNow.Entries.First(e=>e.Login=="new-user").UsePassword(p=>p=="Synthetic-Updated-Password!"); });
                Check("save-updates-existing-without-duplicate",(bool)updated["ok"] && prompts==2 && unique,"same exact host and account reviewed");
                action="cancel";
                var cancelled=Request(new {type="save",token=token,url="https://example.com/",login="cancelled-user",password="Synthetic-Cancelled!"});
                bool absent=false; Ui(delegate { absent=!form.VaultNow.Entries.Any(e=>e.Login=="cancelled-user"); });
                Check("save-cancel-does-not-add-account",!(bool)cancelled["ok"] && absent,"native cancellation");
                action="lock";
                var locked=Request(new {type="save",token=token,url="https://example.com/",login="lock-race-user",password="Synthetic-Lock!"});
                Check("save-lock-race-aborts",!(bool)locked["ok"] && form.VaultNow==null,"secret dialog closed before erasing vault");
            } finally { Ui(delegate {review.Dispose();}); }
            var defaults=Defaults.Load();
            Check("templates-unique",defaults.Templates.Count==defaults.Templates.Select(t=>AppStore.TemplateName(t.Name).ToLowerInvariant()).Distinct().Count(),"canonical account names");
            var old=new List<LoginTemplate> { new LoginTemplate { Name="Steam",Kind="app",Target="custom-steam.exe",Window="Custom Window" },new LoginTemplate {Name="Steam (веб)",Kind="site",Target="https://steamcommunity.com/"},new LoginTemplate {Name="Custom Personal",Group="Мои",Kind="site",Target="https://example.com/private"} };
            AppStore.MergeTemplates(old,defaults.Templates);
            var steam=old.First(t=>t.Name=="Steam Community");
            Check("template-upgrade-merges-app-and-site",old.Count(t=>t.Name=="Steam Community")==1 && steam.Kind=="both" && steam.AppTarget=="custom-steam.exe" && steam.Window=="Custom Window" && old.Any(t=>t.Name=="Custom Personal"),"custom paths and private templates preserved");
            CorrectionUiButtons();
            MainButtonSweep();
            InstallerQueueUiTests();
            BrowserLoginJobTests();
            var prepared=new ComponentVersionInfo {Id="bouncycastle",Installed="2.6.2",Pending="2.7.0",Latest="2.7.0"};
            ComponentInventory.Availability(prepared);
            Check("component-prepared-version-not-offered-again",prepared.Status.Contains("уже подготовлена") && !prepared.Status.Contains("Есть новый"),"runtime remains old until restart; prepared version is considered");
            prepared.Pending=null;prepared.Installed="2.7.0";ComponentInventory.Availability(prepared);
            Check("component-installed-version-not-offered-again",prepared.Status.Contains("не требуется"),"same upstream version after restart");
            prepared.Pending="2.7.0";prepared.Installed="2.6.2";prepared.Latest="2.8.0";ComponentInventory.Availability(prepared);
            Check("component-newer-upstream-requires-compatible-bundle",prepared.Status.Contains("совместимый комплект"),"a developer release is not an installed WinUp update");
        }
        static void LocalApplicationTests() {
            var catalog=new[] {
                new LocalApplication {Name="ChatGPT",Target=LocalApplications.ShellPrefix+"OpenAI.ChatGPT_test!App"},
                new LocalApplication {Name="iCloud",Target=LocalApplications.ShellPrefix+"Apple.iCloud_test!App"},
                new LocalApplication {Name="Steam",Target=LocalApplications.ShellPrefix+"SyntheticSteam"}
            };
            Check("installed-chatgpt-store-app",LocalApplications.Match(catalog,"ChatGPT","https://chatgpt.com/")==catalog[0],"stable Windows app identifier");
            Check("installed-icloud-store-app",LocalApplications.Match(catalog,"iCloud","https://www.icloud.com/")==catalog[1],"stable Windows app identifier");
            Check("installed-steam-service-alias",LocalApplications.Match(catalog,"Steam Community","https://steamcommunity.com/")==catalog[2],"service maps to desktop Steam");
            Check("installed-no-fuzzy-app-choice",LocalApplications.Match(catalog,"ChatGPT Tools","")==null,"similar title never selected automatically");
            Check("installed-ambiguous-app-choice",LocalApplications.Match(catalog.Concat(new[] {new LocalApplication {Name="ChatGPT",Target=LocalApplications.ShellPrefix+"Another.ChatGPT!App"}}),"ChatGPT","")==null,"duplicate editions require explicit picker");
            var launch=LocalApplications.LaunchInfo(catalog[0].Target,"",catalog);
            Check("installed-shell-system-launcher",launch.FileName==System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"explorer.exe") && launch.Arguments=="\""+catalog[0].Target+"\"","known system launcher with quoted catalog identifier");
            bool argsRejected=false;try {LocalApplications.LaunchInfo(catalog[0].Target,"/select,evil",catalog);}catch(InvalidOperationException){argsRejected=true;}
            Check("installed-shell-rejects-extra-arguments",argsRejected,"arguments cannot alter Explorer launch");
            Check("installed-shell-rejects-unknown-id",!LocalApplications.Exists(LocalApplications.ShellPrefix+"Unknown!App",catalog),"must exist in current Windows catalog");
            Check("installed-shell-rejects-injected-id",!LocalApplications.Exists(LocalApplications.ShellPrefix+"Synthetic\" /root,evil",new[] {new LocalApplication {Target=LocalApplications.ShellPrefix+"Synthetic\" /root,evil"}}),"catalog entries do not bypass identifier validation");
            Check("installed-rejects-arbitrary-protocol",!LocalApplications.Exists("evil://launch",catalog),"only installed Windows identifiers and local exe/lnk files");
            string fixture=System.IO.Path.Combine(Paths.Root,"SyntheticInstaller.exe");
            var fileLaunch=LocalApplications.LaunchInfo(fixture,"0",catalog);
            Check("installed-executable-keeps-user-arguments",fileLaunch.FileName==fixture && fileLaunch.Arguments=="0","explicit executable launch");
            Check("installed-missing-app-after-removal",!LocalApplications.Exists(System.IO.Path.Combine(Paths.Root,"removed-application.exe"),catalog),"removed executable cannot start");
            foreach(var item in new[] {new[] {"chrome.exe","chrome://extensions/"},new[] {"msedge.exe","edge://extensions/"},new[] {"brave.exe","brave://extensions/"},new[] {"opera.exe","opera://extensions/"},new[] {"firefox.exe","about:debugging#/runtime/this-firefox"},new[] {"browser.exe","browser://extensions/"}}) {
                var browser=new BrowserInfo {Name=item[0]=="browser.exe" ? "Яндекс Браузер" : item[0],Exe=System.IO.Path.Combine(Paths.Root,item[0])};
                Check("selected-browser-page-"+item[0],BrowserPages.ExtensionUrl(browser)==(item[0]=="firefox.exe" && BrowserSetup.FirefoxPackageReady ? "about:addons" : item[1]),"browser-specific internal page");
            }
            Check("selected-browser-unknown-executable",BrowserPages.ExtensionUrl(new BrowserInfo {Name="Unknown",Exe=fixture})=="","unknown internal protocol not launched");
            var selected=new BrowserInfo {Name="Synthetic selected browser",Exe=fixture};
            var site=BrowserPages.SiteLaunch("https://example.com/settings/passkeys",selected);
            Check("passkey-site-selected-browser",site.FileName==fixture && site.Arguments.Contains("https://example.com/settings/passkeys"),"selected executable rather than system default");
            bool secretRejected=false;try {BrowserPages.SiteLaunch("https://user:password@example.com/",selected);}catch(InvalidOperationException){secretRejected=true;}
            Check("passkey-site-rejects-url-credentials",secretRejected,"login secrets are not placed in launch arguments");
            bool protocolRejected=false;try {BrowserPages.SiteLaunch("evil://launch",selected);}catch(InvalidOperationException){protocolRejected=true;}
            Check("passkey-site-rejects-custom-protocol",protocolRejected,"HTTPS-only site launcher");
        }
        static void BrowserLoginJobTests() {
            Ui(delegate {
                NewVault(false);form.VaultNow.Entries.Clear();
                form.VaultNow.Entries.Add(new LoginEntry {Id="google-demo",Name="Google",Kind="site",Target="https://www.google.com/",Login="shared@example.invalid"});
                form.VaultNow.Entries.Add(new LoginEntry {Id="youtube-demo",Name="YouTube",Kind="site",Target="https://www.youtube.com/",Login2="shared@example.invalid"});
                var matches=MainForm.BrowserSaveMatches(form.VaultNow,"https://accounts.google.com/v3/signin/identifier","shared@example.invalid");
                Check("save-shared-provider-keeps-all-matching-records",matches.Count==2,"same account across services requires a deliberate choice");
                using(var dialog=new BrowserSaveChoiceDialog("https://accounts.google.com",matches)) {
                    dialog.Show(form);Application.DoEvents();
                    var choose=ControlsIn(dialog).OfType<Button>().Single(b=>b.Text=="Выбрать");
                    Check("save-ambiguous-record-has-no-default",dialog.Selected==null && !choose.Enabled,"no automatic overwrite of the first record");
                    ControlsIn(dialog).OfType<ListBox>().Single().SelectedIndex=1;
                    Check("save-ambiguous-record-explicit-selection",dialog.Selected==matches[1] && choose.Enabled,"only the selected record proceeds to review");
                    dialog.DialogResult=DialogResult.Cancel;dialog.Close();
                }
                Lock();
            });
            var legacy=new LoginEntry {Name="GitHub",Kind="site",Target="https://github.com/",LoginUrl="https://github.com/"};
            Check("login-legacy-home-route-uses-login-page",LoginProfiles.Resolve(legacy).LoginUrl=="https://github.com/login","old built-in home link is resolved at runtime");
            legacy.LoginUrl="https://github.com/login?return_to=%2Fsettings";
            Check("login-custom-route-preserved",LoginProfiles.Resolve(legacy).LoginUrl==legacy.LoginUrl,"explicit custom path survives profile updates");
            var youtube=new LoginEntry {Name="YouTube",Kind="site",Target="https://www.youtube.com/"};
            Check("login-reviewed-provider-matches-entry",LoginProfiles.MatchesLoginOrigin(youtube,"https://accounts.google.com/v3/signin/identifier"),"password list/fill/save share the reviewed origin policy");
            Check("login-provider-lookalike-denied",!LoginProfiles.MatchesLoginOrigin(youtube,"https://accounts.google.com.evil.example/login"),"no suffix or arbitrary provider match");
            var cyber=new LoginEntry {Name="CYBERSHOKE",Kind="site",Target="https://cybershoke.net/"};
            Check("login-external-steam-account-is-not-service-password",!LoginProfiles.MatchesLoginOrigin(cyber,"https://steamcommunity.com/login/home/"),"third-party Steam account must be chosen explicitly");
            var sameSite=new LoginEntry {Name="Synthetic custom",Kind="site",Target="https://example.com/"};
            Check("login-custom-unreviewed-subdomain-still-confirms",!LoginProfiles.MatchesLoginOrigin(sameSite,"https://other.example.com/login"),"existing confirmation protection retained");
            const string token="synthetic-login-job-token";string nonce=null;
            Ui(delegate {
                NewVault(true);BrowserPair.Save(token,"Synthetic login jobs");BrowserSetup.Connect();
                var entry=form.VaultNow.Entries[0];entry.Kind="site";entry.Target="https://example.com/";entry.LoginUrl="https://example.com/login";
                var url=form.BeginBrowserLogin(entry);nonce=url.Substring(url.IndexOf("winup-login=",StringComparison.Ordinal)+12);
                Check("login-launch-carries-no-credentials",nonce.Length==64 && !url.Contains(entry.Login) && !url.Contains("Audit-only-secret"),"random expiring capability only");
            });
            var unknown=Request(new {type="login-claim",token=token,nonce=new string('a',64),tab="1",url="https://example.com/login"});
            Check("login-unknown-capability-denied",!(bool)unknown["ok"],"cannot create jobs from a website");
            var origin=Request(new {type="login-claim",token=token,nonce=nonce,tab="1",url="https://evil.example/login"});
            Check("login-wrong-origin-denied",!(bool)origin["ok"] && (string)origin["error"]=="wrong_origin","exact origin includes scheme and port");
            var framed=Request(new {type="login-claim",token=token,nonce=nonce,tab="1",url="https://example.com/login",framed=true});
            Check("login-child-frame-denied",!(bool)framed["ok"],"top page only");
            var claim=Request(new {type="login-claim",token=token,nonce=nonce,tab="1",url="https://example.com/login"});
            Check("login-claim-contains-rules-no-password",(bool)claim["ok"] && claim.ContainsKey("profile") && !claim.ContainsKey("password"),"credentials fetched per stage");
            var otherTab=Request(new {type="login-step",token=token,nonce=nonce,tab="2",url="https://example.com/login",stage="password"});
            Check("login-other-tab-cannot-use-job",!(bool)otherTab["ok"] && (string)otherTab["error"]=="denied","existing tabs receive no data");
            var downgrade=Request(new {type="login-step",token=token,nonce=nonce,tab="1",url="http://example.com/login",stage="password"});
            Check("login-http-downgrade-denied",!(bool)downgrade["ok"],"TLS required outside localhost lab");
            var pw=Request(new {type="login-step",token=token,nonce=nonce,tab="1",url="https://example.com/login",stage="password"});
            Check("login-stage-returns-only-needed-secret",(bool)pw["ok"] && (string)pw["password"]=="Audit-only-secret!" && !pw.ContainsKey("otp") && !pw.ContainsKey("login"),"password stage only");
            var replay=Request(new {type="login-step",token=token,nonce=nonce,tab="1",url="https://example.com/login",stage="password"});
            Check("login-secret-stage-cannot-replay",!(bool)replay["ok"] && (string)replay["error"]=="already_done","single consumption");
            string replacement=null;
            Ui(delegate {var url=form.BeginBrowserLogin(form.VaultNow.Entries[0],true);replacement=url.Substring(url.IndexOf("winup-login=",StringComparison.Ordinal)+12);});
            var stale=Request(new {type="login-claim",token=token,nonce=nonce,tab="1",url="https://example.com/login"});
            Check("login-restart-invalidates-closed-old-tab",!(bool)stale["ok"] && (string)stale["error"]=="not_found","only the new explicit attempt remains valid");
            nonce=replacement;
            Ui(Lock);
            var locked=Request(new {type="login-step",token=token,nonce=nonce,tab="1",url="https://example.com/login",stage="otp"});
            Check("login-lock-removes-job",!(bool)locked["ok"] && !locked.ContainsKey("otp"),"lock invalidates outstanding capabilities");
            BrowserReferenceWorkflowTests();
        }
        static void BrowserReferenceRegression(){
            try{BrowserReferenceWorkflowTests();}catch(Exception ex){Check("browser-reference-workflow-exception",false,ex.ToString());}
            finally{Ui(delegate {form.Close();});}
        }
        static void BrowserReferenceWorkflowTests(){
            const string token="synthetic-reference-workflow";string id=null,sourceId=null,nonce=null;
            Ui(delegate {
                NewVault(false);var v=form.VaultNow;var linked=v.Entries[0];linked.LoginUrl="https://example.com/login";
                var source=new LoginEntry{Name="Shared browser source",Kind="app",Login="shared-user@example.invalid",Password="Synthetic-Shared-Browser!"};
                var secondary=new LoginEntry{Name="Secondary browser source",Kind="app",Login="secondary-user@example.invalid"};
                v.Entries.Add(source);v.Entries.Add(secondary);v.Save();sourceId=source.Id;
                linked.Login=KdbxStore.Reference(source.Id,'U');linked.Login2=KdbxStore.Reference(secondary.Id,'U');linked.Password=KdbxStore.Reference(source.Id,'P');v.Save();id=linked.Id;
                BrowserPair.Save(token,"Synthetic reference workflows");BrowserSetup.Connect();
                Check("browser-save-matches-resolved-primary-login",MainForm.BrowserSaveMatches(v,"https://example.com/login",source.Login).SingleOrDefault()==linked,"shared account is updated rather than added again");
                Check("browser-save-matches-resolved-secondary-login",MainForm.BrowserSaveMatches(v,"https://example.com/login",secondary.Login).SingleOrDefault()==linked,"secondary shared identity is also recognised");
                var launch=form.BeginBrowserLogin(linked);nonce=launch.Substring(launch.IndexOf("winup-login=",StringComparison.Ordinal)+12);
            });
            var list=Request(new{type="list",token=token,url="https://example.com/login"});
            var row=((ArrayList)list["items"]).Cast<Dictionary<string,object>>().Single(r=>(string)r["id"]==id);
            Check("browser-list-displays-resolved-login",(string)row["login"]=="shared-user@example.invalid","account picker shows the actual username");
            var search=Request(new{type="search",token=token,url="https://example.com/login",query="shared-user@example.invalid"});
            Check("browser-search-finds-shared-login",(bool)search["ok"]&&((ArrayList)search["items"]).Count==1,"search includes resolved primary identity");
            search=Request(new{type="search",token=token,url="https://example.com/login",query="secondary-user@example.invalid"});
            Check("browser-search-finds-shared-secondary-login",(bool)search["ok"]&&((ArrayList)search["items"]).Count==1,"search includes resolved secondary identity");
            var claim=Request(new{type="login-claim",token=token,nonce=nonce,tab="references",url="https://example.com/login"});
            Check("browser-shared-login-claim",(bool)claim["ok"],"normal reviewed login job is accepted");
            var user=Request(new{type="login-step",token=token,nonce=nonce,tab="references",url="https://example.com/login",stage="user"});
            Check("browser-login-stage-materializes-both-shared-logins",(bool)user["ok"]&&(string)user["login"]=="shared-user@example.invalid"&&(string)user["login2"]=="secondary-user@example.invalid","site receives usernames rather than reference syntax");
            var pw=Request(new{type="login-step",token=token,nonce=nonce,tab="references",url="https://example.com/login",stage="password"});
            Check("browser-login-stage-materializes-shared-password",(bool)pw["ok"]&&(string)pw["password"]=="Synthetic-Shared-Browser!","password stage keeps shared-field behavior");
            Ui(delegate {var v=form.VaultNow;var source=v.Entries.Single(e=>e.Id==sourceId);v.Entries.Remove(source);v.Save();source.ClearSecrets();});
            list=Request(new{type="list",token=token,url="https://example.com/login"});
            row=((ArrayList)list["items"]).Cast<Dictionary<string,object>>().Single(r=>(string)r["id"]==id);
            Check("browser-list-reports-missing-reference-without-breaking",(bool)list["ok"]&&((string)row["login"]).Contains("недоступен"),"missing source does not make account list disappear");
            Ui(delegate {Check("browser-save-keeps-valid-secondary-when-primary-reference-breaks",MainForm.BrowserSaveMatches(form.VaultNow,"https://example.com/login","secondary-user@example.invalid").Count==1,"independent secondary field still matches");Lock();});
        }
        [System.Runtime.InteropServices.DllImport("user32.dll")] static extern bool EnumWindows(NativeWindowEnum callback,IntPtr value);
        delegate bool NativeWindowEnum(IntPtr hwnd,IntPtr value);
        [System.Runtime.InteropServices.DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd,out uint pid);
        [System.Runtime.InteropServices.DllImport("user32.dll",CharSet=System.Runtime.InteropServices.CharSet.Unicode)] static extern int GetClassName(IntPtr hwnd,StringBuilder name,int size);
        [System.Runtime.InteropServices.DllImport("user32.dll")] static extern IntPtr GetDlgItem(IntPtr hwnd,int id);
        [System.Runtime.InteropServices.DllImport("user32.dll")] static extern bool PostMessage(IntPtr hwnd,int message,IntPtr w,IntPtr l);
        static IEnumerable<Control> ControlsIn(Control root) { foreach(Control child in root.Controls) { yield return child;foreach(var nested in ControlsIn(child))yield return nested; } }
        static void CorrectionUiButtons() {
            Ui(delegate {
                NewVault(false); typeof(MainForm).GetMethod("ShowOpen",Private).Invoke(form,null);
                var tabs=(TabControl)typeof(MainForm).GetField("tabs",Private).GetValue(form);
                var seen=new HashSet<Form>();int managed=0,native=0; Timer cancel=new Timer { Interval=80 };
                cancel.Tick+=delegate {
                    foreach(var dialog in Application.OpenForms.Cast<Form>().ToArray()) {
                        if(dialog==form || !seen.Add(dialog)) continue;
                        if(dialog is Dlg) { managed++; dialog.DialogResult=DialogResult.Cancel;dialog.Close(); }
                    }
                    EnumWindows(delegate(IntPtr hwnd,IntPtr unused) {
                        uint pid;GetWindowThreadProcessId(hwnd,out pid);if(pid!=System.Diagnostics.Process.GetCurrentProcess().Id)return true;
                        var type=new StringBuilder(100);GetClassName(hwnd,type,100);if(type.ToString()!="#32770")return true;
                        native++;int cancelId=GetDlgItem(hwnd,2)!=IntPtr.Zero ? 2 : GetDlgItem(hwnd,7)!=IntPtr.Zero ? 7 : 1;
                        PostMessage(hwnd,0x111,new IntPtr(cancelId),IntPtr.Zero);PostMessage(hwnd,0x10,IntPtr.Zero,IntPtr.Zero);return true;
                    },IntPtr.Zero);
                }; cancel.Start();
                try {
                    foreach(var test in new[] {
                        new[] {"Ключи доступа","Добавить ключ…"},new[] {"Файлы","Создать хранилище"},
                        new[] {"Файлы","Добавить существующее"},new[] {"Файлы","Открыть"},
                        new[] {"Файлы","Зашифровать файлы…"},new[] {"Файлы","Зашифровать папку…"},new[] {"Файлы","Расшифровать пакет…"},new[] {"Файлы","Добавить файлы"},
                        new[] {"Файлы","Добавить папку"},new[] {"Файлы","В Проводнике"},new[] {"Файлы","Новая папка"}
                    }) {
                        tabs.SelectedTab=tabs.TabPages.Cast<TabPage>().First(p=>p.Text==test[0]);
                        var button=ControlsIn(tabs.SelectedTab).OfType<Button>().First(b=>b.Text==test[1]);
                        int before=managed+native;button.PerformClick();
                        Check("ui-button-opens-dialog-"+test[1],managed+native>before,"actual button event and cancellation");
                    }
                } finally {cancel.Dispose();}
                Check("ui-cancel-does-not-open-file-vault",typeof(MainForm).GetField("fileVault",Private).GetValue(form)==null,"all cancelled dialogs leave no decrypted helper");
                Lock();
            });
        }
        static void MainButtonSweep() {
            Ui(delegate {
                NewVault(true);typeof(MainForm).GetMethod("ShowOpen",Private).Invoke(form,null);
                var tabs=(TabControl)typeof(MainForm).GetField("tabs",Private).GetValue(form);
                int dismissed=0;var seen=new HashSet<Form>();
                using(var cancel=new Timer {Interval=70}) {
                    cancel.Tick+=delegate {
                        foreach(var dialog in Application.OpenForms.Cast<Form>().Where(d=>d!=form).ToArray()) {
                            if(!seen.Add(dialog))continue;dismissed++;dialog.DialogResult=DialogResult.Cancel;dialog.Close();
                        }
                        EnumWindows(delegate(IntPtr hwnd,IntPtr unused) {
                            uint pid;GetWindowThreadProcessId(hwnd,out pid);if(pid!=System.Diagnostics.Process.GetCurrentProcess().Id)return true;
                            var type=new StringBuilder(100);GetClassName(hwnd,type,100);if(type.ToString()!="#32770")return true;
                            int cancelId=GetDlgItem(hwnd,2)!=IntPtr.Zero ? 2 : GetDlgItem(hwnd,7)!=IntPtr.Zero ? 7 : 1;
                            PostMessage(hwnd,0x111,new IntPtr(cancelId),IntPtr.Zero);PostMessage(hwnd,0x10,IntPtr.Zero,IntPtr.Zero);return true;
                        },IntPtr.Zero);
                    };cancel.Start();
                    foreach(TabPage page in tabs.TabPages) {
                        tabs.SelectedTab=page;Application.DoEvents();
                        foreach(var view in ControlsIn(page).OfType<ListView>()) {foreach(ListViewItem item in view.Items){item.Selected=false;item.Checked=false;}}
                        foreach(var button in ControlsIn(page).OfType<Button>().ToArray()) {
                            if(!button.Enabled){Check("ui-disabled-button-"+page.Text+"-"+button.Text,true,"disabled in current state");continue;}
                            button.PerformClick();
                            var until=DateTime.UtcNow.AddMilliseconds(120);while(DateTime.UtcNow<until){Application.DoEvents();System.Threading.Thread.Sleep(10);}
                            Check("ui-click-"+page.Text+"-"+button.Text,true,"actual event; no selected records; dialogs cancelled");
                        }
                    }
                }
                Check("ui-cancelled-editors-do-not-add-credentials",form.VaultNow==null || form.VaultNow.Entries.Count==1,"cancellation/no-selection sweep preserves synthetic account");
                Console.WriteLine("INFO ui-sweep cancelled-managed-dialogs="+dismissed);
                Lock();
            });
        }
        static void InstallerQueueUiTests() {
            Ui(delegate {
                string executable=System.IO.Path.Combine(Paths.Root,"SyntheticInstaller.exe");
                var items=new List<AppItem>();
                foreach(int code in new[] {0,23,3010})items.Add(new AppItem {Name="Synthetic exit "+code,File=executable,Args=code.ToString()});
                items.Add(new AppItem {Name="Synthetic missing",File=System.IO.Path.Combine(Paths.Root,"nonexistent-installer.exe")});
                using(var dialog=new InstallForm(items,true))using(var timer=new Timer {Interval=100}) {
                    var close=(Button)typeof(InstallForm).GetField("close",Private).GetValue(dialog);
                    timer.Tick+=delegate {if(close.Enabled)close.PerformClick();};timer.Start();dialog.ShowDialog(form);
                    var rows=((ListView)typeof(InstallForm).GetField("lv",Private).GetValue(dialog)).Items.Cast<ListViewItem>().ToArray();
                    Check("installer-real-exit-zero",rows[0].SubItems[2].Text=="готово" && System.IO.File.Exists(System.IO.Path.Combine(Paths.Root,"synthetic-installer-0.txt")),"actual owned synthetic executable");
                    Check("installer-real-failure-code",rows[1].SubItems[2].Text=="ошибка, код 23","failure is visible per installer");
                    Check("installer-real-reboot-code",rows[2].SubItems[2].Text.Contains("нужна перезагрузка"),"3010 shown accurately");
                    Check("installer-real-missing-file",rows[3].SubItems[2].Text=="файл не найден","queue continues and reports missing file");
                }
                var abortItems=new List<AppItem> {new AppItem {Name="Synthetic waiting",File=executable,Args="-1"},new AppItem {Name="Synthetic next",File=executable,Args="0"}};
                using(var dialog=new InstallForm(abortItems,true))using(var timer=new Timer {Interval=120}) {
                    var close=(Button)typeof(InstallForm).GetField("close",Private).GetValue(dialog);
                    var skip=(Button)typeof(InstallForm).GetField("skip",Private).GetValue(dialog);
                    bool skipped=false;timer.Tick+=delegate {
                        if(!skipped && System.IO.File.Exists(System.IO.Path.Combine(Paths.Root,"synthetic-installer--1.txt"))){skipped=true;skip.PerformClick();}
                        if(close.Enabled)close.PerformClick();
                    };timer.Start();dialog.ShowDialog(form);
                    var rows=((ListView)typeof(InstallForm).GetField("lv",Private).GetValue(dialog)).Items.Cast<ListViewItem>().ToArray();
                    Check("installer-abort-button-stops-only-owned-process",skipped && rows[0].SubItems[2].Text.StartsWith("прервано") && rows[1].SubItems[2].Text=="готово","real button stops waiting fixture and continues queue");
                }
            });
        }
    }
}
