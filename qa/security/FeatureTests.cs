using System;
using System.Collections;
using System.Collections.Generic;
using System.Reflection;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using System.IO;
using System.Linq;
using System.Text;

namespace WinUp
{
    static partial class SecurityHarness
    {
        [System.Runtime.InteropServices.DllImport("kernel32.dll",CharSet=System.Runtime.InteropServices.CharSet.Unicode,SetLastError=true)]
        static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(string name,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
        static FileStream AlternateStream(string path,bool write) {
            var h=CreateFileW(path,write ? 0x40000000u : 0x80000000u,3,IntPtr.Zero,write ? 2u : 3u,0,IntPtr.Zero);
            if(h.IsInvalid) { h.Dispose(); throw new IOException("Synthetic ADS fixture failed"); }
            return new FileStream(h,write ? FileAccess.Write : FileAccess.Read);
        }
        static Dictionary<string, object> Request(object message)
        {
            var json = new JavaScriptSerializer().Serialize(message);
            return Parse((string)typeof(BrowserServer).GetMethod("Dispatch", Private).Invoke(server, new object[] { json }));
        }
        static void FeatureTests()
        {
            const string token = "sandbox-feature-token";
            Ui(delegate { NewVault(true); BrowserPair.Save(token, "Synthetic feature audit"); });
            var list = Request(new { type = "otp-list", token = token });
            var items = (ArrayList)list["items"];
            Check("otp-list-no-seed", (bool)list["ok"] && items.Count == 1 && !new JavaScriptSerializer().Serialize(list).Contains("JBSWY"), "metadata only");
            var code = Request(new { type = "otp", token = token, id = "audit-otp" });
            Check("otp-code-and-expiry", (bool)code["ok"] && ((string)code["otp"]).Length == 6 &&
                Convert.ToInt64(code["expiresAt"]) > Convert.ToInt64(code["serverTime"]) && !code.ContainsKey("secret"), "current code only");
            var linked = Request(new { type = "otp", token = token, id = "audit-entry" });
            Check("otp-linked-entry", (bool)linked["ok"] && (string)linked["id"] == "audit-otp", "site card resolves link");
            var missing = Request(new { type = "otp", token = token, id = "missing" });
            Check("otp-missing", !(bool)missing["ok"] && (string)missing["error"] == "not_found", "no code");
            var insecure = Request(new { type = "otp-fill", token = token, id = "audit-otp", url = "http://example.com" });
            Check("otp-http-rejected", !(bool)insecure["ok"] && (string)insecure["error"] == "insecure", "before any dialog");
            var copy = Request(new { type = "otp-copy", token = token, id = "audit-otp", generation = code["generation"] });
            bool copied = false;
            Ui(delegate { copied = Clipboard.ContainsText() && Clipboard.GetText().Length == 6; });
            Check("otp-copy-native-clipboard", (bool)copy["ok"] && !copy.ContainsKey("otp") && copied, "secret clipboard protections reused");
            int oldGeneration = Convert.ToInt32(code["generation"]);
            Ui(Lock);
            var locked = Request(new { type = "otp", token = token, id = "audit-otp" });
            Check("otp-lock-denies-and-clears", !(bool)locked["ok"] && (string)locked["error"] == "locked" &&
                !UiClipboardHasText(), "locked vault and clipboard");
            Ui(delegate { NewVault(true); });
            var stale = Request(new { type = "otp-copy", token = token, id = "audit-otp", generation = oldGeneration });
            Check("otp-old-session-cannot-copy", !(bool)stale["ok"] && (string)stale["error"] == "locked", "lock/reopen revokes prior popup");
            BrowserPair.Forget(BrowserPair.HashToken(token));
            var unpaired = Request(new { type = "otp", token = token, id = "audit-otp" });
            Check("otp-revoked-pair-denied", !(bool)unpaired["ok"] && (string)unpaired["error"] == "not_paired", "revocation");
            FileFeatureTests();
            PasskeyFeatureTests();
        }
        static void FileFeatureTests()
        {
            string root = Path.Combine(Paths.Root, "file-fixture-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            string encrypted = Path.Combine(root,"encrypted"), source = Path.Combine(root,"source");
            Directory.CreateDirectory(source); Directory.CreateDirectory(Path.Combine(source,"nested"));
            string marker = "SYNTHETIC-FILE-CONTENT-" + Guid.NewGuid().ToString("N");
            File.WriteAllText(Path.Combine(source,"secret.txt"), marker);
            File.WriteAllBytes(Path.Combine(source,"nested","binary.bin"), Enumerable.Range(0, 180000).Select(x => (byte)x).ToArray());
            using (var client = new FileVaultClient(encrypted,"Synthetic-Files-2026-!",true))
            {
                string ads=Path.Combine(root,"ads.txt"); File.WriteAllText(ads,"synthetic");
                using(var stream=AlternateStream(ads+":hidden",true)) { byte[] b=Encoding.UTF8.GetBytes("extra data"); stream.Write(b,0,b.Length); }
                bool rejectedAds=false; try { client.Import(ads,"ads.txt",true); } catch(IOException) { rejectedAds=true; }
                using(var stream=AlternateStream(ads+":hidden",false)) Check("files-ads-preserves-original",rejectedAds && File.Exists(ads) && stream.Length==10,"refuse data-loss move");
                using(var lease=SourceLease.Acquire(Path.Combine(source,"secret.txt"),true)) {
                    bool blocked=false; try { File.WriteAllText(Path.Combine(source,"secret.txt"),"changed"); } catch(IOException) { blocked=true; }
                    Check("files-source-change-blocked",blocked,"original remains stable during verification");
                }
                client.Import(source,"copied",false);
                Check("files-copy-keeps-original", File.Exists(Path.Combine(source,"secret.txt")),"source preserved");
                var listed = client.Call("list", "copied");
                Check("files-folder-roundtrip", ((ArrayList)listed["items"]).Count == 2,"nested folder and file");
                string exported = Path.Combine(root,"export.txt");
                client.Call("export","copied/secret.txt",exported);
                Check("files-decrypt-roundtrip",File.ReadAllText(exported)==marker,"content verified");
                bool collision = false;
                try { client.Import(source,"copied",true); } catch(IOException) { collision = true; }
                Check("files-collision-preserves-original",collision && File.Exists(Path.Combine(source,"secret.txt")),"no overwrite or source deletion");
                client.Import(source,"moved",true);
                Check("files-move-after-verify",!Directory.Exists(source),"verified encrypted copy before deletion");
                bool traversal = false;
                try { client.Call("mkdir","../outside"); } catch(IOException) { traversal=true; }
                Check("files-traversal-rejected",traversal,"cannot escape vault");
                bool mounted=false;
                Check("files-winfsp-detected",WinFspDriver.Installed,"signed driver installed only in Sandbox");
                try {
                    client.Mount("R:\\");
                    File.WriteAllText(@"R:\from-explorer.txt",marker);
                    Check("files-explorer-mounted",File.ReadAllText(@"R:\copied\secret.txt")==marker,"real Windows filesystem");
                    mounted=true;
                } catch(Exception e) { Check("files-explorer-mounted",false,e.Message); }
                if(mounted) client.Call("close");
            }
            Check("files-explorer-unmounted",!Directory.Exists("R:\\"),"drive gone after closing");
            using(var client=new FileVaultClient(encrypted,"Synthetic-Files-2026-!",false)) {
                client.Mount("R:\\");
                Ui(delegate { typeof(MainForm).GetField("fileVault",Private).SetValue(form,client); Lock(); });
                for(int i=0;i<100 && Directory.Exists("R:\\");i++) System.Threading.Thread.Sleep(100);
                Check("files-lock-unmounts-and-stops-helper",!Directory.Exists("R:\\") && !client.Open,"actual MainForm lock closes plaintext drive");
            }
            bool wrong = false;
            try { using(var bad = new FileVaultClient(encrypted,"wrong",false)) {} } catch(IOException) { wrong=true; }
            Check("files-wrong-password",wrong,"no plaintext access");
            string[] data = Directory.GetFiles(encrypted,"*",SearchOption.AllDirectories);
            Check("files-content-and-name-encrypted",!data.Any(x => Path.GetFileName(x).Contains("secret") ||
                Encoding.UTF8.GetString(File.ReadAllBytes(x)).Contains(marker)),"original names and content absent on disk");
            string victim = data.Where(x => x.EndsWith(".c9r") && new FileInfo(x).Length > 32).OrderByDescending(x => new FileInfo(x).Length).First();
            byte[] bytes = File.ReadAllBytes(victim); bytes[bytes.Length-10] ^= 1; File.WriteAllBytes(victim,bytes);
            using(var client = new FileVaultClient(encrypted,"Synthetic-Files-2026-!",false))
            {
                bool rejected=false;
                try { client.Call("export","copied/nested/binary.bin",Path.Combine(root,"tampered.bin")); }
                catch(IOException) { rejected=true; }
                // Which duplicate was selected can differ; try the other verified copy as well.
                if (!rejected) try { client.Call("export","moved/nested/binary.bin",Path.Combine(root,"tampered2.bin")); } catch(IOException) { rejected=true; }
                Check("files-tampered-data-rejected",rejected,"authenticated decryption");
            }
            string cancelVault=Path.Combine(root,"cancel-vault"), big=Path.Combine(root,"cancel-source.bin");
            using(var file=new FileStream(big,FileMode.Create,FileAccess.Write)) file.SetLength(64L*1024*1024);
            using(var client=new FileVaultClient(cancelVault,"Synthetic-Cancel-2026-!",true)) {
                var import=System.Threading.Tasks.Task.Run(delegate { client.Import(big,"cancelled.bin",true); });
                bool started=false;
                for(int i=0;i<300 && !import.IsCompleted;i++) {
                    started=Directory.GetFiles(cancelVault,"*.c9r",SearchOption.AllDirectories).Any(x=>new FileInfo(x).Length>1024*1024);
                    if(started) break; System.Threading.Thread.Sleep(10);
                }
                client.Cancel(); bool failed=false;
                try { import.GetAwaiter().GetResult(); } catch { failed=true; }
                Check("files-cancel-mid-move-preserves-original",started && failed && File.Exists(big) && new FileInfo(big).Length==64L*1024*1024,"cancel during ciphertext write, no source deletion");
            }
            using(var client=new FileVaultClient(cancelVault,"Synthetic-Cancel-2026-!",false))
                Check("files-cancel-vault-reopens",((ArrayList)client.Call("list","")["items"]).Count==0,"partial encrypted stage hidden, vault remains usable");
            var concurrent=new FileVaultClient(cancelVault,"Synthetic-Cancel-2026-!",false);
            System.Threading.Tasks.Task.WaitAll(Enumerable.Range(0,8).Select(x=>System.Threading.Tasks.Task.Run(delegate { concurrent.Dispose(); })).ToArray());
            Check("files-concurrent-close-safe",!concurrent.Open,"simultaneous lock, form close and operation cleanup do not race");
        }
        static bool UiClipboardHasText() { bool yes = false; Ui(delegate { yes = Clipboard.ContainsText(); }); return yes; }
        static object PasskeyOptions(bool create,string rp) {
            string challenge=PasskeyPolicy.Encode(Enumerable.Range(1,32).Select(x=>(byte)x).ToArray());
            if(create) return new { challenge=challenge,rp=new { id=rp,name="Synthetic RP" },
                user=new { id=PasskeyPolicy.Encode(new byte[] {1,2,3,4}), name="sandbox-user",displayName="Sandbox User" },
                pubKeyCredParams=new[] { new { type="public-key",alg=-7 } },attestation="none" };
            return new { challenge=challenge,rpId=rp };
        }
        static void PasskeyFeatureTests() {
            Check("passkey-public-suffix-policy",!PasskeyPolicy.ValidRp("co.uk","login.co.uk") &&
                !PasskeyPolicy.ValidRp("github.io","user.github.io") && PasskeyPolicy.ValidRp("example.co.uk","login.example.co.uk") &&
                !PasskeyPolicy.ValidRp("example.com","example.com.evil.test"),"PSL including private suffixes");
            const string token="sandbox-passkeys";
            Ui(delegate { NewVault(false); BrowserPair.Save(token,"Synthetic passkeys audit"); });
            var bad=Request(new { type="passkey-create",token=token,url="https://attacker.test",requestId=Guid.NewGuid().ToString("N"),publicKey=PasskeyOptions(true,"example.com") });
            Check("passkey-wrong-domain",!(bool)bad["ok"] && (string)bad["error"]=="SecurityError","no key generated");
            var framed=Request(new { type="passkey-create",token=token,url="https://example.com",framed=true,requestId=Guid.NewGuid().ToString("N"),publicKey=PasskeyOptions(true,"example.com") });
            Check("passkey-frame-rejected",!(bool)framed["ok"] && (string)framed["error"]=="SecurityError","top frame only");
            string cancelledId=Guid.NewGuid().ToString("N");
            Request(new { type="passkey-cancel",token=token,requestId=cancelledId });
            var cancelled=Request(new { type="passkey-create",token=token,url="https://example.com",requestId=cancelledId,publicKey=PasskeyOptions(true,"example.com") });
            Check("passkey-cancel-before-start",!(bool)cancelled["ok"] && (string)cancelled["error"]=="AbortError","cancel race handled");
            int approvals=0,passwords=0;
            System.Windows.Forms.Timer timer=null;
            var seen=new HashSet<Form>();
            Ui(delegate {
                timer=new System.Windows.Forms.Timer { Interval=100 };
                timer.Tick+=delegate {
                    foreach(Form dialog in Application.OpenForms.Cast<Form>().ToArray()) {
                        if(seen.Contains(dialog)) continue;
                        if(dialog is PasskeyConsentDialog) { seen.Add(dialog); approvals++; ((Button)typeof(Dlg).GetField("Ok",Private).GetValue(dialog)).PerformClick(); }
                        else if(dialog is PasswordPrompt) {
                            seen.Add(dialog); passwords++;
                            ((TextBox)typeof(PasswordPrompt).GetField("box",Private).GetValue(dialog)).Text=Password;
                            ((Button)typeof(Dlg).GetField("Ok",Private).GetValue(dialog)).PerformClick();
                        }
                    }
                }; timer.Start();
            });
            try {
                var registration=Request(new { type="passkey-create",token=token,url="https://example.com/login",requestId=Guid.NewGuid().ToString("N"),publicKey=PasskeyOptions(true,"example.com") });
                Check("passkey-register-with-consent-and-verification",(bool)registration["ok"] && approvals==1 && passwords==1,"native prompts and real password verification");
                if(!(bool)registration["ok"]) throw new Exception(new JavaScriptSerializer().Serialize(registration));
                string requestId=Guid.NewGuid().ToString("N");
                var assertion=Request(new { type="passkey-get",token=token,url="https://example.com/login",requestId=requestId,publicKey=PasskeyOptions(false,"example.com") });
                Check("passkey-sign-with-consent-and-verification",(bool)assertion["ok"] && approvals==2 && passwords==2,"separate verification for each operation");
                File.WriteAllText(Path.Combine(Paths.Root,"passkey-proof.json"),new JavaScriptSerializer().Serialize(new {registration=registration,assertion=assertion}));
                var replay=Request(new { type="passkey-get",token=token,url="https://example.com/login",requestId=requestId,publicKey=PasskeyOptions(false,"example.com") });
                Check("passkey-request-id-replay-rejected",!(bool)replay["ok"] && (string)replay["error"]=="bad_request","no repeated signing");
                Ui(delegate { form.VaultNow.Save(); });
                int left; StoreResult status; var reopened=KdbxStore.Open(Password,null,out left,out status);
                Check("passkey-kdbx-roundtrip",reopened!=null && reopened.Entries.Count(x=>x.Kind=="passkey")==1,"protected KeePassXC-compatible fields");
                if(reopened!=null) reopened.Lock();
            } finally { Ui(delegate { timer.Dispose(); }); }
            Ui(Lock);
            var locked=Request(new { type="passkey-get",token=token,url="https://example.com",requestId=Guid.NewGuid().ToString("N"),publicKey=PasskeyOptions(false,"example.com") });
            Check("passkey-locked-denied",!(bool)locked["ok"] && (string)locked["error"]=="locked","no signing");
        }
    }
}
