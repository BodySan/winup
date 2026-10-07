// Attack regressions. Runs through the production adapter only on synthetic
// C:\WinUpAudit data; never opens the user's real vault or launches host apps.
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace WinUp
{
    static partial class SecurityHarness
    {
        [DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
        static extern bool DeepSetFileDisposition(Microsoft.Win32.SafeHandles.SafeFileHandle handle, int kind, ref int info, uint size);
        static bool DeepFailsIo(Action action) { try { action(); return false; } catch (IOException) { return true; } }
        static bool DeepStageStarted(string folder, Task task)
        {
            var deadline = DateTime.UtcNow.AddSeconds(30);
            while (!task.IsCompleted && DateTime.UtcNow < deadline)
            {
                try { if (Directory.GetFiles(folder, ".winup-*").Any(x => new FileInfo(x).Length > 1024 * 1024)) return true; }
                catch (IOException) { if (task.IsCompleted) return false; }
                Thread.Sleep(10);
            }
            return false;
        }
        static bool DeepJunction(string link, string target)
        {
            var start = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"),
                "/d /c mklink /J \"" + link + "\" \"" + target + "\"")
                { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            using (var p = Process.Start(start)) { if (!p.WaitForExit(5000)) { p.Kill(); return false; } return p.ExitCode == 0; }
        }
        static void DeepFileTests()
        {
            if (!Paths.Root.StartsWith(@"C:\WinUpAudit\", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Sandbox only");
            string root = Path.Combine(Paths.Root, "deep-files-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            const string marker = "SYNTHETIC-DO-NOT-OVERWRITE";

            string pendingSource = Path.Combine(root, "pending-source.txt"); File.WriteAllText(pendingSource, marker);
            using (var handle = CreateFileW(pendingSource, 0x80010000u, 1, IntPtr.Zero, 3, 0x00200000u, IntPtr.Zero))
            {
                int yes = 1, no = 0; bool marked = DeepSetFileDisposition(handle, 4, ref yes, 4);
                bool blocked;
                using (var ads = CreateFileW(pendingSource + ":attack", 0x40000000u, 7, IntPtr.Zero, 2, 0, IntPtr.Zero)) blocked = ads.IsInvalid;
                bool inspected = true;
                try { typeof(SourceLease).GetMethod("RejectNamedStreams", BindingFlags.NonPublic | BindingFlags.Static, null,
                    new[] { typeof(Microsoft.Win32.SafeHandles.SafeFileHandle) }, null).Invoke(null, new object[] { handle }); }
                catch { inspected = false; }
                bool restored = DeepSetFileDisposition(handle, 4, ref no, 4);
                Check("files-delete-pending-blocks-new-ads", marked && blocked && inspected && restored,
                    "actual NTFS pending disposition blocks new SHARE_DELETE streams while held-handle inspection still works");
            }
            Check("files-delete-pending-rollback-keeps-original", File.ReadAllText(pendingSource) == marker, "cancelled disposition preserves original bytes");

            string transaction = Path.Combine(root, "transaction.zip");
            bool collision = DeepFailsIo(() => Export.WriteFresh(transaction, output => {
                output.WriteByte(42); File.WriteAllText(transaction, marker);
            }));
            Check("export-commit-race-preserves-existing", collision && File.ReadAllText(transaction) == marker &&
                Directory.GetFiles(root, ".winup-export-*").Length == 0, "competing target created after validation is preserved");
            string failedExport = Path.Combine(root, "failed.zip");
            byte[] plaintext = Encoding.UTF8.GetBytes("SYNTHETIC-PRIVATE-PAYLOAD");
            bool failed = false;
            try { Export.ZipAes(failedExport, new List<KeyValuePair<string, byte[]>> {
                new KeyValuePair<string, byte[]>("first.txt", plaintext), new KeyValuePair<string, byte[]>("broken.txt", null)
            }, "Synthetic-Export-Password-2026!"); } catch { failed = true; }
            Check("export-partial-write-does-not-publish", failed && !File.Exists(failedExport) &&
                Directory.GetFiles(root, ".winup-export-*").Length == 0 && plaintext.All(x => x == 0), "failed encrypted archive removed and plaintext buffers cleared");
            string fakeDb = Path.Combine(root, "synthetic.kdbx"), copiedDb = Path.Combine(root, "copy.kdbx");
            File.WriteAllText(fakeDb, marker); Export.CopyEncryptedDatabase(fakeDb, copiedDb);
            Check("export-database-copy-collision", DeepFailsIo(() => Export.CopyEncryptedDatabase(fakeDb, copiedDb)) &&
                File.ReadAllText(copiedDb) == marker, "an existing database export is never replaced");

            var formulaEntry = new LoginEntry { Name = " =HYPERLINK(\"https://example.invalid\")", Kind = "site", Target = "https://example.invalid",
                Login = "\t=1+1", Login2 = "＠SUM(1,2)", Password = "+malicious", Notes = "safe;\"\r\n=escaped-in-one-field" };
            byte[] csvBytes = Export.Csv(new List<LoginEntry> { formulaEntry }, null);
            string csv = Encoding.UTF8.GetString(csvBytes); Array.Clear(csvBytes, 0, csvBytes.Length);
            byte[] textBytes = Export.Text(new List<LoginEntry> { formulaEntry }, null);
            string text = Encoding.UTF8.GetString(textBytes); Array.Clear(textBytes, 0, textBytes.Length); formulaEntry.ClearSecrets();
            Check("export-csv-formula-neutralized", csv.Contains("\"' =HYPERLINK(") && csv.Contains("\"'\t=1+1\"") &&
                csv.Contains("\"'+malicious\"") && csv.Contains("\"'＠SUM(1,2)\"") && csv.Contains("safe;\"\"\r\n=escaped-in-one-field"), "dangerous spreadsheet cells become text; separators stay quoted");
            Check("export-text-retains-exact-secret", text.Contains("Пароль: +malicious\r\n"), "plain text export preserves original password");

            string encrypted = Path.Combine(root, "encrypted"), source = Path.Combine(root, "source"), outside = Path.Combine(root, "outside");
            Directory.CreateDirectory(source); Directory.CreateDirectory(outside);
            File.WriteAllText(Path.Combine(source, "stable.txt"), marker); File.WriteAllText(Path.Combine(outside, "private.txt"), "SYNTHETIC-OUTSIDE-SECRET");
            string big = Path.Combine(root, "large.bin");
            byte[] chunk = Enumerable.Repeat((byte)0x5a, 1024 * 1024).ToArray();
            using (var file = new FileStream(big, FileMode.CreateNew, FileAccess.Write)) for (int i = 0; i < 64; i++) file.Write(chunk, 0, chunk.Length);
            Array.Clear(chunk, 0, chunk.Length);
            string outFolder = Path.Combine(root, "exports"); Directory.CreateDirectory(outFolder);
            using (var client = new FileVaultClient(encrypted, "Synthetic-Deep-Files-2026!", true))
            {
                Check("files-vault-path-rename-blocked", DeepFailsIo(() => Directory.Move(encrypted, encrypted + "-renamed")) && Directory.Exists(encrypted), "open vault root and ancestors are held against redirection");
                using (var lease = SourceLease.Acquire(source, false))
                {
                    File.WriteAllText(Path.Combine(source, "late.txt"), "SYNTHETIC-UNLEASED");
                    string lateLink = Path.Combine(source, "late-link"); bool junction = DeepJunction(lateLink, outside);
                    string manifest = new JavaScriptSerializer().Serialize(lease.Snapshot);
                    client.Call("import", source, "snapshot", manifest);
                    var names = ((ArrayList)client.Call("list", "snapshot")["items"]).Cast<Dictionary<string, object>>().Select(x => (string)x["name"]).ToArray();
                    Check("files-import-uses-locked-snapshot", junction && names.SequenceEqual(new[] { "stable.txt" }) && File.Exists(Path.Combine(source, "late.txt")),
                        "late unheld file and attacker junction are not traversed or imported");
                }
                string reservedSource = Path.Combine(root, "reserved-source"); Directory.CreateDirectory(reservedSource);
                string reserved = Path.Combine(reservedSource, ".winup-import-user.txt"); File.WriteAllText(reserved, marker);
                Check("files-reserved-child-preserves-move", DeepFailsIo(() => client.Import(reservedSource, "reserved", true)) && File.ReadAllText(reserved) == marker,
                    "a user file cannot disappear behind the internal staging filter");
                string lateAdsSource = Path.Combine(root, "late-ads.txt"); File.WriteAllText(lateAdsSource, marker);
                using (var lease = SourceLease.Acquire(lateAdsSource, true))
                {
                    client.Call("import", lateAdsSource, "late-ads.txt", new JavaScriptSerializer().Serialize(lease.Snapshot));
                    var handle = CreateFileW(lateAdsSource + ":late", 0x40000000u, 7, IntPtr.Zero, 2, 0, IntPtr.Zero);
                    bool added = !handle.IsInvalid;
                    if (added) using (var stream = new FileStream(handle, FileAccess.Write)) { stream.WriteByte(99); }
                    else handle.Dispose();
                    bool preserved = DeepFailsIo(lease.DeleteVerifiedOriginals);
                    Check("files-late-ads-preserves-all-originals", added && preserved && File.ReadAllText(lateAdsSource) == marker,
                        "named stream added after encryption is detected before any original deletion");
                }
                client.Import(big, "large.bin", false);
                Check("files-export-inside-ciphertext-rejected", DeepFailsIo(() => client.Call("export", "large.bin", Path.Combine(encrypted, "plaintext.bin"))) &&
                    !File.Exists(Path.Combine(encrypted, "plaintext.bin")) && client.Open, "no plaintext is written into the encrypted storage folder");
                string exportLink = Path.Combine(root, "export-link"); bool exportJunction = DeepJunction(exportLink, outside);
                Check("files-export-junction-rejected", exportJunction && DeepFailsIo(() => client.Call("export", "large.bin", Path.Combine(exportLink, "escape.bin"))) &&
                    !File.Exists(Path.Combine(outside, "escape.bin")) && client.Open, "a chosen reparse destination does not redirect plaintext");
                string destination = Path.Combine(outFolder, "raced.bin");
                var export = Task.Run(() => client.Call("export", "large.bin", destination));
                bool started = DeepStageStarted(outFolder, export);
                bool parentBlocked = started && DeepFailsIo(() => Directory.Move(outFolder, outFolder + "-redirected"));
                if (started) File.WriteAllText(destination, marker);
                bool raceRejected = DeepFailsIo(() => export.GetAwaiter().GetResult());
                Check("files-export-racing-target-preserved", started && raceRejected && File.ReadAllText(destination) == marker &&
                    Directory.GetFiles(outFolder, ".winup-export-*").Length == 0, "target added during 64 MiB decryption is never overwritten");
                Check("files-export-parent-rename-blocked", parentBlocked && Directory.Exists(outFolder), "directory handle prevents redirecting an in-progress export");

                string drive = Enumerable.Range('D', 'Z' - 'D' + 1).Reverse().Select(c => (char)c + ":\\").FirstOrDefault(x => !Directory.Exists(x));
                if (drive == null) { Check("files-import-racing-target-preserved", false, "no free test drive"); }
                else
                {
                    client.Mount(drive);
                    var import = Task.Run(() => client.Import(big, "raced-import.bin", true));
                    bool importStarted = DeepStageStarted(drive, import);
                    string target = Path.Combine(drive, "raced-import.bin");
                    if (importStarted) File.WriteAllText(target, marker);
                    bool importRejected = DeepFailsIo(() => import.GetAwaiter().GetResult());
                    Check("files-import-racing-target-preserved", importStarted && importRejected && File.ReadAllText(target) == marker &&
                        File.Exists(big) && new FileInfo(big).Length == 64L * 1024 * 1024, "competing mounted file and move source both survive the collision");
                }
            }
            using (var client = new FileVaultClient(encrypted, "Synthetic-Deep-Files-2026!", false))
            {
                string cancelDestination = Path.Combine(outFolder, "cancelled.bin");
                var export = Task.Run(() => client.Call("export", "large.bin", cancelDestination));
                bool started = DeepStageStarted(outFolder, export); client.Cancel();
                bool cancelled = DeepFailsIo(() => export.GetAwaiter().GetResult());
                Check("files-cancel-export-removes-plaintext-stage", started && cancelled && !File.Exists(cancelDestination) &&
                    Directory.GetFiles(outFolder, ".winup-export-*").Length == 0, "kill during decryption cleans the exact parent-owned plaintext staging file");
            }
        }
    }
}
