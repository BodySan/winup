// Runs only in C:\WinUpAudit inside Windows Sandbox, on synthetic data.
// Builds the unchanged production sources with a separate test entry point.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace WinUp
{
    static partial class SecurityHarness
    {
        static MainForm form;
        static BrowserServer server;
        static int failures;
        const string Password = "Synthetic-Audit-7w$2026";
        const BindingFlags Private = BindingFlags.NonPublic | BindingFlags.Instance;
        [DllImport("user32.dll")] static extern IntPtr SendMessage(IntPtr hwnd, int message, IntPtr w, IntPtr l);

        static NotifyIcon TrayNotify()
        {
            var tray = typeof(MainForm).GetField("tray", Private).GetValue(form);
            return (NotifyIcon)typeof(TrayIcon).GetField("icon", Private).GetValue(tray);
        }
        static void TrayMouse(int message)
        {
            IntPtr hwnd = IntPtr.Zero;
            Ui(delegate { hwnd = ((NativeWindow)typeof(NotifyIcon).GetField("window", Private).GetValue(TrayNotify())).Handle; });
            // .NET Framework NotifyIcon callback: WM_USER + 1024, mouse event in lParam.
            SendMessage(hwnd, 0x800, IntPtr.Zero, new IntPtr(message));
        }
        static int ProbeMemory(GCHandle pinned, int length, string hash)
        {
            var info = new ProcessStartInfo(Path.Combine(Paths.Root, "MemoryProbe.exe"),
                Process.GetCurrentProcess().Id + " " + pinned.AddrOfPinnedObject().ToInt64() + " " + length + " " + hash)
                { UseShellExecute = false, CreateNoWindow = true };
            using (var process = Process.Start(info))
            {
                if (!process.WaitForExit(5000)) { process.Kill(); return 4; }
                return process.ExitCode;
            }
        }

        [STAThread]
        static int Main(string[] args)
        {
            if (!Paths.Root.StartsWith(@"C:\WinUpAudit\", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Run only from isolated sandbox audit directory");
            AppDomain.CurrentDomain.AssemblyResolve += delegate(object s, ResolveEventArgs e)
            { return new AssemblyName(e.Name).Name == "KeePassLib" ? CoreLoader.Resolve() : EmbeddedModules.Resolve(e.Name); };
            if(args.Length>0 && args[0].StartsWith("chrome-extension://")) { BrowserBridge.Run(args[0]); return 0; }
            Application.EnableVisualStyles();
            Directory.CreateDirectory(Paths.Apps);
            Directory.CreateDirectory(Paths.Data);
            var store = new AppStore();
            store.Settings.WizardDone = true;
            store.Settings.FillNotify = false;
            store.Settings.AutoLockMinutes = 1440; // race tests explicitly trigger locking
            bool trayUi = Array.IndexOf(args, "--tray-ui") >= 0;
            if (trayUi) store.Settings.HideFromCapture = false; // synthetic UI lab only
            store.Settings.BackupDir = Path.Combine(Paths.Root, "backup");
            store.Save();
            form = new MainForm(store);
            server = (BrowserServer)typeof(MainForm).GetField("browserServer", Private).GetValue(form);
            if (!trayUi) form.Shown += delegate { Task.Run((Action)Tests); };
            Application.Run(form);
            Console.WriteLine("TOTAL failures=" + failures);
            return failures == 0 ? 0 : 1;
        }

        static void Ui(Action action) { form.Invoke((MethodInvoker)delegate { action(); }); }
        static void Check(string name, bool ok, string detail)
        { Console.WriteLine((ok ? "PASS " : "FAIL ") + name + " " + detail); if (!ok) failures++; }
        static void SetVault(KdbxStore v) { typeof(MainForm).GetField("vault", Private).SetValue(form, v); }
        static void Lock() { typeof(MainForm).GetMethod("LockVault", Private).Invoke(form, null); }
        static string Fill(string url, bool framed, string token)
        {
            BrowserPair.Save(token, "Synthetic sandbox audit");
            return (string)typeof(BrowserServer).GetMethod("Fill", Private).Invoke(server,
                new object[] { token, url, "audit-entry", framed });
        }
        static Dictionary<string, object> Parse(string json)
        { return new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(json); }
        static void NewVault(bool otp)
        {
            var v = KdbxStore.Create(Password, null);
            v.Entries.Add(new LoginEntry { Id = "audit-entry", Name = "Synthetic", Target = new string("https://example.com".ToCharArray()),
                Login = new string("audit-user".ToCharArray()), Password = new string("Audit-only-secret!".ToCharArray()),
                TwoFa = otp ? "link" : "none", OtpId = "audit-otp" });
            if (otp) v.Otp.Add(new OtpEntry { Id = "audit-otp", Secret = new string("JBSWY3DPEHPK3PXP".ToCharArray()), Period = 10 });
            SetVault(v);
        }
        static void Tests()
        {
            try
            {
                Thread.Sleep(1000);
                // Attack a synthetic database on disk, never a host user's vault.
                Ui(delegate { NewVault(false); form.VaultNow.Save(); });
                byte[] original = File.ReadAllBytes(KdbxStore.KdbxFile);
                Check("vault-no-plaintext", !Encoding.UTF8.GetString(original).Contains("Audit-only-secret!"), "encrypted file");
                Ui(Lock);
                int left;
                StoreResult status;
                var wrong = KdbxStore.Open("incorrect-audit-password", null, out left, out status);
                Check("vault-wrong-password", wrong == null && status == StoreResult.Wrong, "remaining=" + left);
                var reopened = KdbxStore.Open(Password, null, out left, out status);
                Check("vault-correct-password", reopened != null && reopened.Entries[0].Password == "Audit-only-secret!", "round trip");
                if (reopened != null) reopened.Lock();
                byte[] damaged = (byte[])original.Clone();
                damaged[damaged.Length - 20] ^= 1;
                File.WriteAllBytes(KdbxStore.KdbxFile, damaged);
                bool rejected = false;
                try
                {
                    var altered = KdbxStore.Open(Password, null, out left, out status);
                    rejected = altered == null;
                    if (altered != null) altered.Lock();
                }
                catch { rejected = true; }
                finally { File.WriteAllBytes(KdbxStore.KdbxFile, original); }
                Check("vault-tamper-rejected", rejected, "flipped encrypted payload byte");
                Ui(delegate { NewVault(false); form.VaultNow.Entries[0].Password = Guid.NewGuid().ToString("N"); });
                ProtectedMemoryTests();
                StorageAndExportTests();
                CoreIntegrityTests();
                ComponentUpdateTests();
                FeatureTests();
                Ui(delegate { NewVault(false); });
                var good = Parse(Fill("https://example.com/login", false, "test-good"));
                Check("https-fill", (bool)good["ok"] && (string)good["password"] == "Audit-only-secret!", "synthetic credentials returned");
                foreach (var url in new[] { "http://example.com/login", "http:\\example.com/login", "http:/example.com/login", "http:example.com/login" })
                {
                    string host = SiteDomain.HostOf(url);
                    if (host != "example.com") { Check("url-rejected", true, url); continue; }
                    var r = Parse(Fill(url, false, "test-" + url));
                    Check("http-downgrade", !(bool)r["ok"] && Convert.ToString(r["error"]) == "insecure", url);
                }
                // Keep the request waiting for a fresh OTP, then lock through the real UI handler.
                Ui(delegate { Lock(); NewVault(true); });
                while (Totp.SecondsLeftFor(10) > 2) Thread.Sleep(50);
                var pending = Task.Run(delegate { return Fill("https://example.com", false, "test-race"); });
                Thread.Sleep(250);
                Check("otp-request-waiting", !pending.IsCompleted, "request active before lock");
                Ui(Lock);
                if (!pending.Wait(15000)) throw new TimeoutException("OTP request did not finish");
                var afterLock = Parse(pending.Result);
                Check("lock-cancels-pending-fill", !(bool)afterLock["ok"] && Convert.ToString(afterLock["error"]) == "locked",
                    "response ok=" + afterLock["ok"] + "; contains-secret=" + pending.Result.Contains("Audit-only-secret!"));

                // Change an entry while its authorized request waits for a fresh OTP.
                Ui(delegate { NewVault(true); });
                while (Totp.SecondsLeftFor(10) > 2) Thread.Sleep(50);
                var changed = Task.Run(delegate { return Fill("https://example.com", false, "test-edit-race"); });
                Thread.Sleep(250);
                Check("edit-request-waiting", !changed.IsCompleted, "request active before edit");
                Ui(delegate { form.VaultNow.Entries[0].Target = "https://different.example.org"; });
                if (!changed.Wait(15000)) throw new TimeoutException("Edited request did not finish");
                var edited = Parse(changed.Result);
                Check("edit-cancels-pending-fill", !(bool)edited["ok"] && !changed.Result.Contains("Audit-only-secret!"),
                    "response ok=" + edited["ok"] + "; contains-secret=" + changed.Result.Contains("Audit-only-secret!"));
                Ui(Lock);

                Ui(delegate { NewVault(true); });
                while (Totp.SecondsLeftFor(10) > 2) Thread.Sleep(50);
                var revoked = Task.Run(delegate { return Fill("https://example.com", false, "test-revoke"); });
                Thread.Sleep(250);
                Check("revoke-request-waiting", !revoked.IsCompleted, "request active before revocation");
                BrowserPair.Forget(BrowserPair.HashToken("test-revoke"));
                if (!revoked.Wait(15000)) throw new TimeoutException("Revoked request did not finish");
                var revokeResult = Parse(revoked.Result);
                Check("revoke-cancels-pending-fill", !(bool)revokeResult["ok"] && Convert.ToString(revokeResult["error"]) == "not_paired" && !revoked.Result.Contains("Audit-only-secret!"),
                    "error=" + revokeResult["error"]);
                foreach (var json in new[] { "{", "null", "[]", "{\"type\":\"fill\",\"token\":\"unpaired\",\"url\":\"https://example.com\",\"id\":\"audit-entry\"}" })
                {
                    string result = (string)typeof(BrowserServer).GetMethod("Dispatch", Private).Invoke(server, new object[] { json });
                    Check("invalid-or-unpaired-request", !(bool)Parse(result)["ok"] && !result.Contains("Audit-only-secret!"), result);
                }
                Ui(Lock);

                // A local untrusted process sends no JSON. It must be rejected before reading.
                var clients = new List<NamedPipeClientStream>();
                int threadsBefore = Process.GetCurrentProcess().Threads.Count, connected = 0;
                try
                {
                    for (int i = 0; i < 105; i++)
                    {
                        var c = new NamedPipeClientStream(".", BrowserPipe.Name, PipeDirection.InOut);
                        try { c.Connect(250); clients.Add(c); connected++; } catch { c.Dispose(); }
                    }
                    Thread.Sleep(600);
                    int extra = Process.GetCurrentProcess().Threads.Count - threadsBefore;
                    Check("idle-pipe-flood", extra < 20 && connected == 105, "connected=" + connected + "; extra-threads=" + extra);
                }
                finally { foreach (var c in clients) c.Dispose(); }
                Thread.Sleep(600);
                using (var c = new NamedPipeClientStream(".", BrowserPipe.Name, PipeDirection.InOut))
                {
                    c.Connect(3000);
                    var read = Task.Run(delegate { return new StreamReader(c).ReadLine(); });
                    if (!read.Wait(3000)) { c.Dispose(); Check("reject-without-json", false, "still waiting for attacker input"); }
                    else Check("reject-without-json", read.Result != null && read.Result.Contains("bad_caller"), "no request body sent");
                }
                Ui(delegate
                {
                    var toggle = form.MainMenuStrip.Items.OfType<ToolStripMenuItem>().First().DropDownItems
                        .OfType<ToolStripMenuItem>().Single(x => x.Text == "Сворачивать в трей");
                    if (toggle.Checked) toggle.PerformClick();
                    toggle.PerformClick();
                    Check("tray-toggle-does-not-minimize", toggle.Checked && form.Visible && form.WindowState != FormWindowState.Minimized, "setting only");
                    Check("tray-setting-persisted", AppStore.Load().Settings.MinimizeToTray, "saved to settings");
                    form.WindowState = FormWindowState.Maximized;
                });
                // Exercise OS minimize and NotifyIcon event routing, not ShowFromTray directly.
                SendMessage(form.Handle, 0x112, new IntPtr(0xF020), IntPtr.Zero);
                Ui(delegate { Check("minimize-button-to-tray", !form.Visible, "hidden=" + !form.Visible); });
                TrayMouse(0x201); TrayMouse(0x202);
                Ui(delegate { Check("tray-single-click-restore", form.Visible && form.WindowState == FormWindowState.Maximized, "state=" + form.WindowState); });
                SendMessage(form.Handle, 0x112, new IntPtr(0xF020), IntPtr.Zero);
                TrayMouse(0x203); TrayMouse(0x202);
                Ui(delegate { Check("tray-double-click-restore", form.Visible && form.WindowState == FormWindowState.Maximized, "state=" + form.WindowState); });
                SendMessage(form.Handle, 0x112, new IntPtr(0xF020), IntPtr.Zero);
                Ui(delegate
                {
                    ((ToolStripMenuItem)TrayNotify().ContextMenuStrip.Items[0]).PerformClick();
                    Check("tray-menu-restore", form.Visible && form.WindowState == FormWindowState.Maximized, "state=" + form.WindowState);
                    var toggle = form.MainMenuStrip.Items.OfType<ToolStripMenuItem>().First().DropDownItems
                        .OfType<ToolStripMenuItem>().Single(x => x.Text == "Сворачивать в трей");
                    toggle.PerformClick();
                    Check("tray-setting-disabled-persisted", !AppStore.Load().Settings.MinimizeToTray, "saved to settings");
                });
                SendMessage(form.Handle, 0x112, new IntPtr(0xF020), IntPtr.Zero);
                Ui(delegate { Check("disabled-tray-normal-minimize", form.Visible && form.WindowState == FormWindowState.Minimized, "normal taskbar minimize"); });
            }
            catch (Exception e) { failures++; Console.WriteLine("ERROR " + e); }
            finally { form.BeginInvoke((MethodInvoker)delegate { form.Close(); }); }
        }
    }
}
