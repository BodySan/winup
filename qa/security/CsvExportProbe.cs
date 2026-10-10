using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Windows.Forms;
using System.Drawing;
using System.Runtime.InteropServices;
using Microsoft.VisualBasic.FileIO;

namespace WinUp
{
    // Synthetic transfer records, parsed by a library independent of WinUp.
    internal static class CsvExportProbe
    {
        static int failed, passed;
        static void Check(string name, bool ok)
        {
            Console.WriteLine((ok ? "PASS " : "FAIL ") + name);
            if (ok) passed++; else failed++;
        }

        [STAThread] static int Main(string[] args)
        {
            AppDomain.CurrentDomain.AssemblyResolve += (s, e) =>
                new AssemblyName(e.Name).Name == "KeePassLib" ? CoreLoader.Resolve() : EmbeddedModules.Resolve(e.Name);
            Application.EnableVisualStyles();
            try { Transfer(); Dialog(); if (args.Contains("--ui")) Workflow(); }
            catch (Exception e) { Console.WriteLine(e); failed++; }
            Console.WriteLine("RESULT passed=" + passed + " failed=" + failed);
            return failed == 0 ? 0 : 1;
        }

        static List<string[]> Parse(byte[] bytes)
        {
            var rows = new List<string[]>();
            using (var reader = new TextFieldParser(new MemoryStream(bytes), Encoding.UTF8))
            {
                reader.SetDelimiters(","); reader.HasFieldsEnclosedInQuotes = true; reader.TrimWhiteSpace = false;
                while (!reader.EndOfData) rows.Add(reader.ReadFields());
            }
            return rows;
        }

        static void Transfer()
        {
            var entries = new List<LoginEntry>();
            var otp = new OtpEntry { Id = "synthetic-otp", Issuer = "Учебный сервис", Account = "тест", Secret = "JBSWY3DPEHPK3PXP" };
            byte[] bytes = null;
            try
            {
                string[] secrets = { "=1+1", "+unchanged", "-secret", "@secret", "  пароль,\"кавычки\";😀  ", "line1\r\nline2", "\tlogin-secret" };
                foreach (var secret in secrets)
                    entries.Add(new LoginEntry { Name = "Учебный, \"сервис\"", Target = "https://example.invalid/login?q=1,2", Login = "  @пользователь,\"имя\"  ", Password = secret,
                        Notes = "Заметка, \"текст\"\r\nВторая строка", TwoFa = "link", OtpId = otp.Id, Login2 = "SECONDARY-NOT-EXPORTED", RecoveryCodes = "RECOVERY-NOT-EXPORTED" });
                entries.Add(new LoginEntry { Kind = "passkey", Name = "Test passkey", Target = "https://example.invalid/", Password = "PRIVATE-KEY-NOT-EXPORTED" });
                entries.Add(new LoginEntry { Kind = "app", Target = @"C:\Synthetic\app.exe", Password = "APP-NOT-EXPORTED" });
                entries.Add(new LoginEntry { Target = "https://example.invalid/", Password = "" });
                entries.Add(new LoginEntry { Target = "https://user:secret@example.invalid/", Password = "BAD-URL-NOT-EXPORTED" });
                var linked = new LoginEntry { Target = "https://linked.invalid/", Login = "{REF:USER}", Password = "{REF:PASS}" };
                linked.ResolveField = value => value == "{REF:USER}" ? "linked-user" : value == "{REF:PASS}" ? new string("Linked-password!".ToCharArray()) : value;
                entries.Add(linked);
                int count, skipped;
                bytes = Export.ManagerCsv(entries, new List<OtpEntry> { otp }, out count, out skipped);
                var rows = Parse(bytes);
                Check("csv-one-common-schema", rows[0].SequenceEqual(new[] { "Title", "URL", "Username", "Password", "Notes", "OTPAuth" }) && rows.All(r => r.Length == 6));
                Check("csv-comma-quotes-unicode-and-multiline-roundtrip", rows[1][0] == entries[0].Name && rows[1][1] == entries[0].Target && rows[1][2] == entries[0].Login && rows[1][4] == entries[0].Notes);
                Check("csv-credentials-retain-formula-prefixes-and-whitespace", secrets.Select((secret, i) => rows[i + 1][3] == secret).All(ok => ok));
                Check("csv-skips-passkeys-and-unusable-records-with-counts", count == secrets.Length + 1 && skipped == 4 && rows.Count == count + 1);
                Check("csv-materializes-shared-login-and-password", rows.Last()[2] == "linked-user" && rows.Last()[3] == "Linked-password!");
                string otpUri = otp.Uri();
                try { Check("csv-linked-two-factor-uri-retained", rows[1][5] == otpUri); }
                finally { Secure.Wipe(otpUri); }
                string text = Encoding.UTF8.GetString(bytes);
                try
                {
                    Check("csv-excludes-private-keys-recovery-codes-and-secondary-login", !text.Contains("NOT-EXPORTED"));
                    using (var imported = PasswordImport.Parse(text, new LoginEntry[0]))
                        Check("csv-import-roundtrip-with-notes-and-two-factor", imported.Rows.Count == count && imported.Rows[0].Entry.UsePassword(p => p == secrets[0]) && imported.Rows[0].Entry.Login == entries[0].Login && imported.Rows[0].Otp != null);
                }
                finally { Secure.Wipe(text); }
                string path = Path.Combine(Paths.Root, "synthetic-transfer.csv");
                if (File.Exists(path)) File.Delete(path);
                Export.WriteFresh(path, fs => fs.Write(bytes, 0, bytes.Length));
                Check("csv-written-file-parses-with-independent-reader", Parse(File.ReadAllBytes(path)).Count == rows.Count);
                bool refused = false;
                try { Export.WriteFresh(path, fs => fs.WriteByte(0)); } catch (IOException) { refused = true; }
                Check("csv-existing-export-is-never-overwritten", refused && File.ReadAllBytes(path).SequenceEqual(bytes));
                File.Delete(path);
                Check("csv-transfer-utf8-without-bom", bytes.Length > 3 && !(bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf));
                linked.ResolveField = value => { throw new IOException("Synthetic missing referenced entry"); };
                bool broken = false;
                try { byte[] unexpected = Export.ManagerCsv(entries, null, out count, out skipped); Array.Clear(unexpected, 0, unexpected.Length); } catch (IOException) { broken = true; }
                Check("csv-broken-reference-refuses-incomplete-transfer", broken && !File.Exists(path));
            }
            finally { if (bytes != null) Array.Clear(bytes, 0, bytes.Length); foreach (var e in entries) e.ClearSecrets(); otp.ClearSecret(); }
        }

        static T Field<T>(ExportDialog dialog, string name)
        { return (T)typeof(ExportDialog).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic).GetValue(dialog); }

        static void Dialog()
        {
            using (var dialog = new ExportDialog())
            {
                Field<CheckBox>(dialog, "kdbx").Checked = false;
                Field<CheckBox>(dialog, "csv").Checked = true;
                Field<RadioButton>(dialog, "mine").Checked = true;
                Field<TextBox>(dialog, "own").Text = "x";
                Check("csv-only-selection-does-not-require-archive-key", dialog.Csv && !dialog.Kdbx && !dialog.Zip && dialog.OwnKey == null && !Field<TextBox>(dialog, "own").Enabled);
                Field<CheckBox>(dialog, "zip").Checked = true;
                Check("csv-plus-zip-enables-archive-key", dialog.Csv && dialog.Zip && Field<TextBox>(dialog, "own").Enabled && dialog.OwnKey == "x");
                Field<CheckBox>(dialog, "zip").Checked = false;
                Check("csv-switching-back-disables-unneeded-key", dialog.OwnKey == null && !Field<CheckBox>(dialog, "show").Enabled);
            }
        }

        static IEnumerable<Control> Children(Control parent)
        { foreach (Control child in parent.Controls) { yield return child; foreach (var item in Children(child)) yield return item; } }

        delegate bool Visitor(IntPtr window, IntPtr state);
        [DllImport("user32.dll")] static extern bool EnumWindows(Visitor visitor, IntPtr state);
        [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window, out uint pid);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr window, StringBuilder text, int length);
        [DllImport("user32.dll")] static extern IntPtr GetDlgItem(IntPtr window, int id);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr window, StringBuilder text, int length);
        [DllImport("user32.dll")] static extern bool PostMessage(IntPtr window, uint message, IntPtr w, IntPtr l);

        static void Workflow()
        {
            if (Environment.UserName != "WDAGUtilityAccount" || !Paths.Root.StartsWith(@"C:\WinUpAudit\csv-", StringComparison.OrdinalIgnoreCase))
                throw new Exception("UI workflow requires a fresh synthetic Sandbox folder");
            const string password = "Synthetic-CSV-Workflow-2026!";
            const BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
            Directory.CreateDirectory(Paths.Data); Directory.CreateDirectory(Paths.Apps);
            var settings = new AppStore(); settings.Settings.WizardDone = true; settings.Settings.HideFromCapture = false;
            settings.Settings.AutoLockMinutes = 1440; settings.Settings.BackupDir = Path.Combine(Paths.Root, "backups"); settings.Save();
            using (var form = new MainForm(settings))
            {
                var vault = KdbxStore.Create(password, null);
                try
                {
                    vault.Entries.Add(new LoginEntry { Name = "Учебный аккаунт", Target = "https://example.invalid/", Login = "synthetic-user", Password = "+Synthetic-secret!" });
                    vault.Entries.Add(new LoginEntry { Kind = "passkey", Name = "Учебный ключ", Target = "https://example.invalid/", Password = "Synthetic-private-key" });
                    vault.Save(); byte[] original = File.ReadAllBytes(KdbxStore.KdbxFile);
                    typeof(MainForm).GetField("vault", flags).SetValue(form, vault);
                    form.Show(); typeof(MainForm).GetMethod("ShowOpen", flags).Invoke(form, null); Application.DoEvents();
                    for (int scenario = 0; scenario < 3; scenario++)
                    {
                        bool cancel = scenario == 2, archive = scenario == 1;
                        string folder = Path.Combine(Paths.Root, "export-" + scenario); Directory.CreateDirectory(folder);
                        string message = ""; bool sawDialog = false;
                        DateTime deadline = DateTime.UtcNow.AddSeconds(30);
                        using (var closer = new System.Threading.Timer(state =>
                        {
                            if (DateTime.UtcNow > deadline) { Console.WriteLine("FAIL CSV UI workflow timeout"); Environment.Exit(1); }
                            uint expected = (uint)System.Diagnostics.Process.GetCurrentProcess().Id;
                            EnumWindows((window, ignored) =>
                            {
                                uint pid; GetWindowThreadProcessId(window, out pid); if (pid != expected) return true;
                                var type = new StringBuilder(80); GetClassName(window, type, type.Capacity); if (type.ToString() != "#32770") return true;
                                var text = new StringBuilder(4000); GetWindowText(GetDlgItem(window, 65535), text, text.Capacity);
                                message = text.ToString();
                                PostMessage(window, 0x10, IntPtr.Zero, IntPtr.Zero);
                                return true;
                            }, IntPtr.Zero);
                        }, null, 0, 100))
                        using (var timer = new Timer { Interval = 100 })
                        {
                            timer.Tick += (s, e) =>
                            {
                                timer.Stop();
                                try
                                {
                                foreach (var prompt in Application.OpenForms.Cast<Form>().OfType<PasswordPrompt>().ToArray())
                                {
                                    Children(prompt).OfType<TextBox>().First().Text = password;
                                    Children(prompt).OfType<Button>().Single(b => b.DialogResult == DialogResult.OK).PerformClick();
                                }
                                foreach (var dialog in Application.OpenForms.Cast<Form>().OfType<ExportDialog>().ToArray())
                                {
                                    sawDialog = true;
                                    Field<CheckBox>(dialog, "kdbx").Checked = archive;
                                    Field<CheckBox>(dialog, "zip").Checked = archive;
                                    Field<CheckBox>(dialog, "csv").Checked = true;
                                    Field<TextBox>(dialog, "folder").Text = folder;
                                    Field<RadioButton>(dialog, "mine").Checked = true;
                                    Field<TextBox>(dialog, "own").Text = archive ? Export.NewKey() : "x";
                                    dialog.PerformLayout(); dialog.Refresh();
                                    if (scenario == 0)
                                    {
                                        Field<TextBox>(dialog, "folder").Text = @"C:\WinUp — экспорт";
                                        using (var bitmap = new Bitmap(dialog.Width, dialog.Height))
                                        { dialog.DrawToBitmap(bitmap, new Rectangle(Point.Empty, dialog.Size)); bitmap.Save(@"C:\WinUp\test\csv-export\export-dialog.png"); }
                                        Field<TextBox>(dialog, "folder").Text = folder;
                                        Check("csv-dialog-actions-and-format-are-visible", Children(dialog).OfType<Button>().Where(b => b.Visible).All(b => b.Bottom <= b.Parent.ClientSize.Height) && Field<CheckBox>(dialog, "csv").Visible);
                                    }
                                    Children(dialog).OfType<Button>().Single(b => b.DialogResult == (cancel ? DialogResult.Cancel : DialogResult.OK)).PerformClick();
                                }
                                }
                                finally { timer.Start(); }
                            };
                            timer.Start(); typeof(MainForm).GetMethod("ExportPasswords", flags).Invoke(form, null); timer.Stop();
                        }
                        string[] csvFiles = Directory.GetFiles(folder, "*.csv");
                        Check("csv-ui-workflow-" + scenario, sawDialog && (cancel ? Directory.GetFiles(folder).Length == 0 : csvFiles.Length == 1 && Parse(File.ReadAllBytes(csvFiles[0]))[1][3] == "+Synthetic-secret!" && message.Contains("сохранено записей — 1") && message.Contains("— 1")));
                        if (archive) Check("csv-ui-combined-kdbx-zip-and-csv", Directory.GetFiles(folder, "*.kdbx").Length == 1 && Directory.GetFiles(folder, "*.zip").Length == 1);
                        Check("csv-ui-export-does-not-change-database-" + scenario, File.ReadAllBytes(KdbxStore.KdbxFile).SequenceEqual(original));
                    }
                    form.Close();
                }
                finally { vault.Lock(); }
            }
        }
    }
}
