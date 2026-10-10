// Test entry point only. Production sources unchanged; isolated synthetic Sandbox profile.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Windows.Forms;

namespace WinUp {
    static class FeatureUiHarness {
        static readonly string Password=NewPassword();
        static string NewPassword(){var bytes=new byte[32];using(var rng=System.Security.Cryptography.RandomNumberGenerator.Create())rng.GetBytes(bytes);try{return Convert.ToBase64String(bytes);}finally{Array.Clear(bytes,0,bytes.Length);}}
        const string Token="b1a77fc0887665443322110000ffeeddccbbaa99887766554433221100ffeedd";
        const BindingFlags Private=BindingFlags.Instance|BindingFlags.NonPublic;
        [STAThread] static void Main(string[] args) {
            if(Environment.UserName!="WDAGUtilityAccount")throw new Exception("Windows Sandbox only");
            if(!Paths.Root.StartsWith(@"C:\WinUpAudit\feature-browser",StringComparison.OrdinalIgnoreCase)) throw new Exception("Sandbox synthetic lab only");
            if(args.Length==2 && args[0]=="--stage-package") { ComponentResources.Store.Install(args[1]); return; }
            if(args.Length>0 && args[0].StartsWith("chrome-extension://")) { BrowserBridge.Run(args[0]); return; }
            if(args.Length>=2 && args[1]==BrowserSetup.FirefoxId) { BrowserBridge.Run(args[1]); return; }
            AppDomain.CurrentDomain.AssemblyResolve+=(s,e)=>new AssemblyName(e.Name).Name=="KeePassLib" ? CoreLoader.Resolve() : EmbeddedModules.Resolve(e.Name);
            Application.EnableVisualStyles();
            Directory.CreateDirectory(Paths.Data); Directory.CreateDirectory(Paths.Apps);
            var store=new AppStore(); store.Settings.WizardDone=true; store.Settings.FillNotify=false;
            store.Settings.HideFromCapture=false; store.Settings.AutoLockMinutes=1440; store.Settings.BackupDir=Path.Combine(Paths.Root,"backup"); store.Save();
            WindowsHello.Disable(); BrowserPair.Save(Token,"Synthetic browser lab"); BrowserSetup.Connect();
            var form=new MainForm(store);
            Action open=delegate {
                if(form.VaultNow!=null) form.VaultNow.Lock();
                var vault=KdbxStore.Create(Password,null);
                vault.Otp.Add(new OtpEntry { Id="ui-otp",Issuer="Synthetic Test",Account="sandbox-user",Secret="JBSWY3DPEHPK3PXP" });
                vault.Entries.Add(new LoginEntry { Id="ui-site",Name="Synthetic Test",Kind="both",Target="http://localhost:9265",Login="sandbox-user",Login2="synthetic@example.com",RecoveryCodes="Synthetic-Recovery-1\nSynthetic-Recovery-2",Password="Synthetic-Site-Password!",TwoFa="link",OtpId="ui-otp" });
                typeof(MainForm).GetField("vault",Private).SetValue(form,vault);
                typeof(MainForm).GetMethod("ShowOpen",Private).Invoke(form,null);
                typeof(MainForm).GetMethod("RefreshPasskeys",Private).Invoke(form,null);
            };
            form.Shown+=(s,e)=>open();
            var seen=new HashSet<Form>(); var timer=new Timer { Interval=100 };
            timer.Tick+=delegate {
                string control=@"C:\WinUp\test\features\browser-command.txt";
                if(File.Exists(control)) {
                    string command=File.ReadAllText(control).Trim(); File.Delete(control);
                    File.AppendAllText(@"C:\WinUp\test\features\command-proof.txt",DateTime.UtcNow.ToString("o")+" pid="+System.Diagnostics.Process.GetCurrentProcess().Id+" command="+command+"\n");
                    if(command=="lock") typeof(MainForm).GetMethod("LockVault",Private).Invoke(form,null);
                    if(command=="lock") File.AppendAllText(@"C:\WinUp\test\features\command-proof.txt","locked="+(form.VaultNow==null)+" generation="+form.BrowserGeneration+"\n");
                    if(command=="reopen") open();
                    if(command=="passkey-occlusion") form.WindowState=FormWindowState.Maximized;
                    if(command=="passkey-normal") form.WindowState=FormWindowState.Normal;
                    if(command=="confirmation-entry") {
                        form.VaultNow.Entries.Add(new LoginEntry {Id="ui-confirmation",Name="Synthetic Foreign",Kind="site",Target="http://different.example.invalid/",Login="confirmation-user",Password="Synthetic-Confirmation-Password!"});
                    }
                    if(command=="many-entries") {
                        for(int i=0;i<40;i++)form.VaultNow.Entries.Add(new LoginEntry {Id="ui-extra-"+i,Name="ZZ Synthetic Extra "+i.ToString("D2"),Kind="site",Target="http://localhost:9265/",Login="extra-user-"+i,Password="Synthetic-Extra-Password!"});
                    }
                    if(command=="login-flow") {
                        var entry=form.VaultNow.Entries.First(e=>e.Name=="Synthetic Test");
                        entry.LoginUrl="http://localhost:9265/flow/user";entry.AutoEnter=true;
                        File.WriteAllText(@"C:\WinUp\test\corrections\flow-launch.txt",form.BeginBrowserLogin(entry));
                    }
                    if(command=="reference-fields") {
                        open();var database=form.VaultNow;var entry=database.Entries.First(e=>e.Name=="Synthetic Test");
                        var main=new LoginEntry{Name="Synthetic primary source",Kind="app",Login="sandbox-user",Password="Synthetic-Site-Password!"};
                        var secondary=new LoginEntry{Name="Synthetic secondary source",Kind="app",Login="synthetic@example.com"};
                        database.Entries.Add(main);database.Entries.Add(secondary);database.Save();
                        entry.Login=KdbxStore.Reference(main.Id,'U');entry.Login2=KdbxStore.Reference(secondary.Id,'U');entry.Password=KdbxStore.Reference(main.Id,'P');
                        entry.LoginUrl="http://localhost:9265/flow/user";entry.AutoEnter=true;database.Save();
                        File.WriteAllText(@"C:\WinUp\test\corrections\flow-launch.txt",form.BeginBrowserLogin(entry));
                        File.WriteAllText(@"C:\WinUp\test\advanced-1.18\reference-fixture-ready.txt","ready");
                    }
                    if(command.StartsWith("launch-button|",StringComparison.Ordinal)) {
                        string[] parts=command.Split('|');
                        if(parts.Length!=3 || (parts[2]!="first" && parts[2]!="second"))throw new Exception("Unexpected launch fixture");
                        var browser=Browsers.Installed().Single(b=>Path.GetFileName(b.Exe).Equals(parts[1],StringComparison.OrdinalIgnoreCase));
                        var entry=form.VaultNow.Entries.First(e=>e.Id=="ui-site");
                        entry.Kind="site";entry.Target="https://example.com/";entry.LoginUrl="https://example.com/?winup-launch="+parts[2];entry.Browser=browser.Name;entry.AutoEnter=false;
                        typeof(MainForm).GetMethod("RefreshEntries",Private).Invoke(form,null);
                        var list=(ListView)typeof(MainForm).GetField("pwList",Private).GetValue(form);
                        foreach(ListViewItem row in list.Items)row.Selected=((LoginEntry)row.Tag).Id==entry.Id;
                        FindButton(form,"Войти").PerformClick();
                        File.AppendAllText(@"C:\WinUp\test\login-1.15.1\launch-button-native.txt",browser.Name+" "+parts[2]+" actual-button-click\n");
                        File.AppendAllText(@"C:\WinUp\test\login-1.15.1\launch-button-native.txt",((TextBox)typeof(MainForm).GetField("pwLog",Private).GetValue(form)).Text+"\n");
                    }
                    if(command=="exit") form.Close();
                }
                foreach(Form dialog in Application.OpenForms.Cast<Form>().ToArray()) {
                    if(seen.Contains(dialog)) continue;
                    if(dialog is PasskeyConsentDialog) {
                        seen.Add(dialog); ((Button)typeof(Dlg).GetField("Ok",Private).GetValue(dialog)).PerformClick();
                    } else if(dialog is EntryDialog && dialog.Text.Contains("localhost")) {
                        seen.Add(dialog); ((Button)typeof(Dlg).GetField("Ok",Private).GetValue(dialog)).PerformClick();
                    } else if(dialog is ConfirmFillDialog) {
                        seen.Add(dialog);
                        File.AppendAllText(@"C:\WinUp\test\login-1.15.1\confirmation-dialog-proof.txt",DateTime.UtcNow.ToString("o")+" visible="+dialog.Visible+" native-confirmation\n");
                        ((Button)typeof(Dlg).GetField("Ok",Private).GetValue(dialog)).PerformClick();
                    } else if(dialog is PasswordPrompt && (dialog.Text.Contains("localhost") || File.Exists(Path.Combine(Paths.Root,"github-test-enabled")) && dialog.Text=="WinUp: ключ доступа для github.com")) {
                        seen.Add(dialog); ((TextBox)typeof(PasswordPrompt).GetField("box",Private).GetValue(dialog)).Text=Password;
                        ((Button)typeof(Dlg).GetField("Ok",Private).GetValue(dialog)).PerformClick();
                    }
                }
            }; timer.Start();
            Application.Run(form); timer.Dispose();
        }
        static Button FindButton(Control parent,string text) {
            foreach(Control child in parent.Controls) {
                var button=child as Button;if(button!=null && button.Text==text)return button;
                var found=FindButton(child,text);if(found!=null)return found;
            }
            return null;
        }
    }
}
