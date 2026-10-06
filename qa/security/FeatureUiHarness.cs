// Test entry point only. Production sources unchanged; isolated synthetic Sandbox profile.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Windows.Forms;

namespace WinUp {
    static class FeatureUiHarness {
        const string Password="Synthetic-Feature-UI-2026!";
        const string Token="b1a77fc0887665443322110000ffeeddccbbaa99887766554433221100ffeedd";
        const BindingFlags Private=BindingFlags.Instance|BindingFlags.NonPublic;
        [STAThread] static void Main(string[] args) {
            if(!Paths.Root.StartsWith(@"C:\WinUpAudit\feature-browser",StringComparison.OrdinalIgnoreCase)) throw new Exception("Sandbox synthetic lab only");
            if(args.Length==2 && args[0]=="--stage-package") { ComponentResources.Store.Install(args[1]); return; }
            if(args.Length>0 && args[0].StartsWith("chrome-extension://")) { BrowserBridge.Run(args[0]); return; }
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
                vault.Entries.Add(new LoginEntry { Id="ui-site",Name="Synthetic Test",Target="http://localhost:9265",Login="sandbox-user",Password="Synthetic-Site-Password!",TwoFa="link",OtpId="ui-otp" });
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
                    if(command=="exit") form.Close();
                }
                foreach(Form dialog in Application.OpenForms.Cast<Form>().ToArray()) {
                    if(seen.Contains(dialog)) continue;
                    if(dialog is PasskeyConsentDialog) {
                        seen.Add(dialog); ((Button)typeof(Dlg).GetField("Ok",Private).GetValue(dialog)).PerformClick();
                    } else if(dialog is PasswordPrompt && dialog.Text.Contains("localhost")) {
                        seen.Add(dialog); ((TextBox)typeof(PasswordPrompt).GetField("box",Private).GetValue(dialog)).Text=Password;
                        ((Button)typeof(Dlg).GetField("Ok",Private).GetValue(dialog)).PerformClick();
                    }
                }
            }; timer.Start();
            Application.Run(form); timer.Dispose();
        }
    }
}
