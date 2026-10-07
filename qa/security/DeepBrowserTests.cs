using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Diagnostics;
using System.Threading;
using System.Windows.Forms;

namespace WinUp {
    static partial class SecurityHarness {
        static void DesktopTargetTests() {
            string title="WinUp synthetic duplicate-title "+Guid.NewGuid().ToString("N");
            string trusted=Path.Combine(Paths.Root,"DesktopWindowFixture.exe"), foreign=Path.Combine(Paths.Root,"ForeignWindowFixture.exe");
            string trustedProof=Path.Combine(Paths.Root,"desktop-trusted-window.txt"), foreignProof=Path.Combine(Paths.Root,"desktop-foreign-window.txt");
            if(!File.Exists(trusted) || !File.Exists(foreign)) throw new Exception("Synthetic desktop window fixtures missing");
            if(File.Exists(trustedProof)) File.Delete(trustedProof); if(File.Exists(foreignProof)) File.Delete(foreignProof);
            Process good=null,bad=null;
            try {
                good=Process.Start(new ProcessStartInfo(trusted,"\""+title+"\" \""+trustedProof+"\"") {UseShellExecute=false,WindowStyle=ProcessWindowStyle.Normal});
                bad=Process.Start(new ProcessStartInfo(foreign,"\""+title+"\" \""+foreignProof+"\"") {UseShellExecute=false,WindowStyle=ProcessWindowStyle.Normal});
                var deadline=DateTime.UtcNow.AddSeconds(10);
                while((!File.Exists(trustedProof) || !File.Exists(foreignProof)) && DateTime.UtcNow<deadline) Thread.Sleep(50);
                IntPtr goodWindow=new IntPtr(long.Parse(File.ReadAllText(trustedProof).Split('|')[0]));
                IntPtr badWindow=new IntPtr(long.Parse(File.ReadAllText(foreignProof).Split('|')[0]));
                string reason;var binding=DesktopTarget.Create(trusted,out reason);
                Check("desktop-executable-owned-window-accepted",binding!=null && binding.Matches(goodWindow),"real subprocess window belongs to selected exe");
                Check("desktop-same-title-foreign-process-rejected",binding!=null && !binding.Matches(badWindow),"same title and identical binary content do not equal same file identity");
                Check("desktop-title-search-filters-process",Win.Find(title,binding.Matches)==goodWindow,"title alone never selects a foreign process");
                Check("desktop-title-search-no-verified-window",Win.Find(title,h=>false)==IntPtr.Zero,"no title-only fallback");
                var packaged=DesktopTarget.Create(LocalApplications.ShellPrefix+"Synthetic.Package_0000000000000!App",out reason);
                Check("desktop-unconfirmed-package-window-rejected",packaged!=null && !packaged.Verify(goodWindow,out reason) && !string.IsNullOrEmpty(reason),"unpackaged executable cannot impersonate a package AUMID");
                Check("desktop-unverified-or-missing-target-rejected",DesktopTarget.Create(null,out reason)==null && DesktopTarget.Create(Path.Combine(Paths.Root,"missing.exe"),out reason)==null,
                    "a title without a usable target cannot authorize input");
                string shortcut=Path.Combine(Paths.Root,"synthetic-desktop-target.lnk");
                Ui(delegate {
                    object shell=null,link=null;
                    try {
                        shell=Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell"));
                        link=shell.GetType().InvokeMember("CreateShortcut",BindingFlags.InvokeMethod,null,shell,new object[] {shortcut});
                        link.GetType().InvokeMember("TargetPath",BindingFlags.SetProperty,null,link,new object[] {trusted});
                        link.GetType().InvokeMember("Save",BindingFlags.InvokeMethod,null,link,new object[0]);
                    } finally {
                        if(link!=null && System.Runtime.InteropServices.Marshal.IsComObject(link))System.Runtime.InteropServices.Marshal.FinalReleaseComObject(link);
                        if(shell!=null && System.Runtime.InteropServices.Marshal.IsComObject(shell))System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shell);
                    }
                    var linked=DesktopTarget.Create(shortcut,out reason);
                    Check("desktop-shortcut-binds-resolved-executable",linked!=null && linked.Matches(goodWindow) && !linked.Matches(badWindow),"read-only IShellLink target used, not shortcut name/title");
                });
                good.Kill();good.WaitForExit(3000);
                Check("desktop-closed-window-identity-rejected",!binding.Verify(goodWindow,out reason),"stale HWND does not authorize input");
                if(File.Exists(shortcut)) File.Delete(shortcut);
            } finally {
                foreach(var process in new[] {good,bad}) if(process!=null) {try {if(!process.HasExited) {process.Kill();process.WaitForExit(3000);}}catch{}process.Dispose();}
            }
        }
        // Synthetic state only; run by the guarded Windows Sandbox harness.
        static void DeepBrowserTests() {
            DesktopTargetTests();
            Check("private-hosting-tenants-isolated", !SiteDomain.SameSite("one.azurestaticapps.net","two.azurestaticapps.net") &&
                !SiteDomain.SameSite("one.s3.amazonaws.com","two.s3.amazonaws.com") &&
                !SiteDomain.SameSite("one.workers.dev","two.workers.dev") &&
                !SiteDomain.SameSite("one.fly.dev","two.fly.dev"), "complete PSL replaces incomplete password suffix table");
            Check("psl-wildcard-and-exception-password-policy", !SiteDomain.SameSite("a.foo.kawasaki.jp","b.bar.kawasaki.jp") &&
                SiteDomain.SameSite("a.city.kawasaki.jp","b.city.kawasaki.jp"), "PSL wildcard and exception rules");
            Check("ordinary-subdomains-still-match", SiteDomain.SameSite("accounts.google.com","www.google.com") &&
                SiteDomain.SameSite("login.example.co.nz","www.example.co.nz"), "ordinary sites preserve subdomain matching");
            Check("domain-userinfo-rejected", SiteDomain.HostOf("https://google.com@attacker.test/")==null, "ambiguous credential URLs fail closed");
            Check("idn-and-trailing-dot-normalized", SiteDomain.SameHost(SiteDomain.HostOf("https://пример.рф/"),SiteDomain.HostOf("https://xn--e1afmkfd.xn--p1ai./")), "IDNA and DNS root dot are consistent");
            Check("passkey-ip-rp-rejected", !PasskeyPolicy.ValidRp("127.0.0.1","127.0.0.1") && !PasskeyPolicy.ValidRp("192.168.1.1","192.168.1.1"), "RP ID must be a domain");
            Check("browser-publisher-exact-match", Signature.OrganizationMatches("Google LLC","Google") &&
                Signature.OrganizationMatches("Brave Software, Inc.","Brave") && !Signature.OrganizationMatches("Not Google LLC","Google") &&
                !Signature.OrganizationMatches("Mozilla Corporation Evil","Mozilla"), "substring resemblance never grants trust");

            const string token="deep-browser-revocation-synthetic";
            Ui(delegate { NewVault(false); BrowserPair.Save(token,"Synthetic revocation"); });
            var list=Request(new {type="list",token=token,url="https://example.com/"});
            Check("paired-browser-list-available", (bool)list["ok"], "authorized synthetic listing works");
            var malformed=Request(new {type="passkey-get",token=token,url="https://example.com/",requestId=Guid.NewGuid().ToString("N"),
                publicKey=new {challenge=PasskeyPolicy.Encode(new byte[32]),rpId="example.com",allowCredentials="invalid filter"}});
            Check("passkey-malformed-allow-list-rejected", !(bool)malformed["ok"] && (string)malformed["error"]=="TypeError", "invalid filters cannot silently become discoverable account selection");
            var malformedId=Request(new {type="passkey-get",token=token,url="https://example.com/",requestId=Guid.NewGuid().ToString("N"),
                publicKey=new {challenge=PasskeyPolicy.Encode(new byte[32]),rpId="example.com",allowCredentials=new[] {new {type="public-key",id="%invalid"}}}});
            Check("passkey-malformed-credential-id-rejected", !(bool)malformedId["ok"] && (string)malformedId["error"]=="TypeError", "invalid binary descriptor fails before prompting");
            EntryDialog editor=null; TextBox unfinished=null;
            Ui(delegate {
                editor=new EntryDialog(new LoginEntry {Name="Synthetic draft",Target="https://example.com"},new AppStore(),true,form.VaultNow.Otp);
                unfinished=(TextBox)typeof(EntryDialog).GetField("login2",Private).GetValue(editor);
                unfinished.Text="unsaved-synthetic-draft"; editor.Show(form); Application.DoEvents();
            });
            try {
                var nested=Request(new {type="passkey-create",token=token,url="https://example.com/",requestId=Guid.NewGuid().ToString("N"),publicKey=PasskeyOptions(true,"example.com")});
                bool preserved=false; Ui(delegate { preserved=editor.Visible && unfinished.Text=="unsaved-synthetic-draft"; });
                Check("passkey-background-request-preserves-existing-editor",!(bool)nested["ok"] && (string)nested["error"]=="busy" && preserved,
                    "a background website cannot nest consent and later close an unrelated draft");
            } finally { Ui(delegate { editor.Close(); editor.Dispose(); }); }
            Ui(delegate { BrowserPair.Forget(BrowserPair.HashToken(token)); });
            // Model a request that passed Dispatch before revocation and was queued
            // waiting for the UI thread. The final access must recheck authorization.
            string denied=(string)typeof(BrowserServer).GetMethod("ListOrSearch",Private).Invoke(server,new object[] {token,"https://example.com/",null});
            var response=new System.Web.Script.Serialization.JavaScriptSerializer().Deserialize<Dictionary<string,object>>(denied);
            Check("queued-list-rechecks-revoked-pairing", !(bool)response["ok"] && (string)response["error"]=="not_paired", "no metadata leaves a revoked queued request");

            string edge=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),@"Microsoft\Edge\Application\msedge.exe");
            if(!File.Exists(edge)) throw new Exception("Real signed Edge fixture missing in Sandbox");
            string copy=Path.Combine(Paths.Root,"signature-metadata-replacement.exe");
            File.Copy(edge,copy,true);
            bool trusted=Signature.SignedBy(copy,"Microsoft");
            DateTime stamp=File.GetLastWriteTimeUtc(copy); long size=new FileInfo(copy).Length;
            using(var file=new FileStream(copy,FileMode.Open,FileAccess.ReadWrite,FileShare.None)) {
                file.Position=0x40; int value=file.ReadByte(); file.Position=0x40; file.WriteByte((byte)(value^1));
            }
            File.SetLastWriteTimeUtc(copy,stamp);
            bool rejected=!Signature.SignedBy(copy,"Microsoft");
            Check("signed-browser-replacement-preserving-metadata-rejected",trusted && rejected && new FileInfo(copy).Length==size && File.GetLastWriteTimeUtc(copy)==stamp,
                "actual signed browser bytes tampered at unchanged path/length/mtime");
            File.Delete(copy);
            Ui(Lock);
        }
    }
}
