// Practical regressions against production sources; synthetic Sandbox data only.
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using Microsoft.Win32;

namespace WinUp
{
    static partial class SecurityHarness
    {
        static void ProtectedMemoryTests()
        {
            var secret = new SecretText();
            string input = new string(Guid.NewGuid().ToString("N").ToCharArray());
            secret.Set(input);
            string copy = secret.Read();
            Check("protected-secret-roundtrip", copy == input && !ReferenceEquals(copy, input), "caller owns transient copy");
            Secure.Wipe(copy);
            string scoped = null;
            try { secret.Use<int>(text => { scoped = text; throw new InvalidOperationException(); }); } catch (InvalidOperationException) { }
            Check("scoped-secret-cleared-on-throw", scoped.All(c => c == '\0'), "exception cleanup");
            var encrypted = (SecretBytes)typeof(SecretText).GetField("value", Private).GetValue(secret);
            var buffer = (byte[])typeof(SecretBytes).GetField("protectedData", Private).GetValue(encrypted);
            var clearBytes = Encoding.Unicode.GetBytes(input);
            Check("retained-buffer-is-protected", !buffer.Take(clearBytes.Length).SequenceEqual(clearBytes), "Windows SameProcess protection");
            var pin = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                Check("external-memory-probe-runs", ProbeMemory(pin, buffer.Length, CoreLoader.Sha256(buffer)) == 0, "separate process reads ciphertext at known address");
                secret.Clear();
                Check("retained-buffer-cleared", buffer.All(b => b == 0) && ProbeMemory(pin, buffer.Length, CoreLoader.Sha256(new byte[buffer.Length])) == 0,
                    "retained ciphertext overwritten on clear");
            }
            finally { pin.Free(); Secure.Wipe(input); Array.Clear(clearBytes, 0, clearBytes.Length); }
            Ui(Lock);
        }

        static bool SecretMatches(LoginEntry entry, string expected) { return entry.UsePassword(pw => pw == expected); }
        static void StorageAndExportTests()
        {
            Ui(delegate { NewVault(true); form.VaultNow.Save(); });
            var v = form.VaultNow;
            int left; StoreResult status;
            var reopened = KdbxStore.Open(Password, null, out left, out status);
            Check("password-and-otp-roundtrip", reopened != null && SecretMatches(reopened.Entries[0], "Audit-only-secret!") &&
                reopened.Otp[0].UseSecret(s => s == "JBSWY3DPEHPK3PXP"), "save/reopen protected model");
            reopened.Lock();
            var pin = v.MakePin("71492638");
            KdbxStore unlocked;
            Check("wrong-pin-rejected", KdbxStore.OpenWithPin("00000000", pin, out unlocked) == StoreResult.Wrong && unlocked == null, "authenticated wrapper");
            Check("correct-pin-roundtrip", KdbxStore.OpenWithPin("71492638", pin, out unlocked) == StoreResult.Ok && SecretMatches(unlocked.Entries[0], "Audit-only-secret!"), "protected PIN session");
            unlocked.Lock(); pin.Clear();
            Check("cleared-pin-rejected", KdbxStore.OpenWithPin("71492638", pin, out unlocked) == StoreResult.Wrong, "expired/disabled session");
            var material = v.KeyMaterial();
            try
            {
                Check("hello-key-material-roundtrip", KdbxStore.OpenWithKey(material, out unlocked) == StoreResult.Ok && SecretMatches(unlocked.Entries[0], "Audit-only-secret!"), "existing serialized format");
                unlocked.Lock();
            }
            finally { Array.Clear(material, 0, material.Length); }
            foreach (var raw in new[] { new byte[0], new byte[7], new byte[] { 255,255,255,127,0,0,0,0 }, new byte[] { 0,0,0,0,255,255,255,255 } })
                Check("malformed-key-material-rejected", KdbxStore.OpenWithKey(raw, out unlocked) == StoreResult.Wrong && unlocked == null, "length=" + raw.Length);

            Ui(delegate
            {
                using (var d = new EntryDialog(v.Entries[0], new AppStore(), false, v.Otp))
                {
                    var box = (TextBox)typeof(EntryDialog).GetField("pass", Private).GetValue(d);
                    Check("entry-dialog-retains-display", box.Text == "Audit-only-secret!", "native field survives scoped plaintext cleanup");
                }
                using (var d = new OtpDialog(v.Otp[0], false))
                {
                    var box = (TextBox)typeof(OtpDialog).GetField("secret", Private).GetValue(d);
                    Check("otp-dialog-retains-display", box.Text == "JBSWY3DPEHPK3PXP", "native field survives scoped plaintext cleanup");
                }
            });
            var recovery = v.MakeRecoveryCode(); v.Save();
            try
            {
                var restored = KdbxStore.OpenByRecovery(recovery, out left, out status);
                Check("recovery-roundtrip", restored != null && SecretMatches(restored.Entries[0], "Audit-only-secret!"), "separate recovery KDBX");
                restored.Lock();
                v.SetDbPassword("New-Synthetic-Audit-Password-2026", null); v.Save();
                restored = KdbxStore.Open("New-Synthetic-Audit-Password-2026", null, out left, out status);
                Check("master-change-preserves-recovery", restored != null && restored.HasRecovery, "protected code rewrapped");
                restored.Lock();
                restored = KdbxStore.OpenByRecovery(recovery, out left, out status);
                Check("recovery-after-master-change", restored != null && SecretMatches(restored.Entries[0], "Audit-only-secret!"), "old recovery code still usable");
                restored.Lock();
            }
            finally { Secure.Wipe(recovery); }

            var csv = Export.Csv(v.Entries, v.Otp);
            var text = Export.Text(v.Entries, v.Otp);
            var links = Export.OtpLinks(v.Otp);
            Check("export-contains-expected-values", Encoding.UTF8.GetString(csv).Contains("Audit-only-secret!") && Encoding.UTF8.GetString(links).Contains("JBSWY3DPEHPK3PXP"), "format regression");
            string zipPath = Path.Combine(Paths.Root, "audit-export.zip");
            var files = new List<KeyValuePair<string, byte[]>> { new KeyValuePair<string, byte[]>("passwords.csv", csv), new KeyValuePair<string, byte[]>("passwords.txt", text), new KeyValuePair<string, byte[]>("otp.txt", links) };
            Export.ZipAes(zipPath, files, "Synthetic-Zip-7x$Long-Audit-Key");
            Check("export-clears-inputs", files.All(f => f.Value.All(b => b == 0)), "CSV/text/OTP arrays consumed");
            Check("encrypted-export-no-plaintext", !Encoding.UTF8.GetString(File.ReadAllBytes(zipPath)).Contains("Audit-only-secret!"), "AE-2 archive only on disk");
            var failureBuffer = Encoding.UTF8.GetBytes("SYNTHETIC-EXPORT-FAILURE");
            bool failed = false;
            try { Export.ZipAes(Paths.Root, new List<KeyValuePair<string,byte[]>> { new KeyValuePair<string,byte[]>("failure.txt", failureBuffer) }, "Synthetic-Zip-7x$Long-Audit-Key"); }
            catch { failed = true; }
            Check("export-failure-clears-inputs", failed && failureBuffer.All(b => b == 0), "unwritable output directory");
            Check("weak-export-key-rejected", Export.KeyProblem("aaaaaaaaaaaaaaaaaaaa") != null && Export.KeyProblem("Synthetic-Zip-7x$Long-Audit-Key") == null, "quality validation");

            Ui(Lock);
            var keyPath = Path.Combine(Paths.Root, "synthetic.key");
            File.WriteAllBytes(keyPath, Vault.Random(32));
            v = KdbxStore.Create(Password, keyPath);
            v.Entries.Add(new LoginEntry { Name = "Synthetic key-file", Password = "Synthetic-Keyfile-Entry" }); v.Save();
            material = v.KeyMaterial(); v.Lock();
            try
            {
                Check("keyfile-material-roundtrip", KdbxStore.OpenWithKey(material, out unlocked) == StoreResult.Ok && SecretMatches(unlocked.Entries[0], "Synthetic-Keyfile-Entry"), "keyfile and Hello/PIN representation");
                unlocked.Lock();
            }
            finally { Array.Clear(material, 0, material.Length); }
            v = KdbxStore.Open(Password, keyPath, out left, out status);
            Check("keyfile-open", v != null && !File.Exists(Path.Combine(Paths.Data,"kf.tmp")), "no keyfile copy in shared data");
            bool reduced = false;
            try { v.CalibrateKdf(32, 500); } catch (ArgumentOutOfRangeException) { reduced = true; }
            Check("kdf-reduction-rejected", reduced, "memory floor");
            var tuning = v.CalibrateKdf(64, 500);
            Check("kdf-calibration", tuning.Iterations >= 8 && tuning.Milliseconds > 0, "64 MiB; iterations=" + tuning.Iterations + "; ms=" + tuning.Milliseconds);
            v.ApplyKdf(tuning); v.Save(); v.Lock();
            v = KdbxStore.Open(Password, keyPath, out left, out status);
            Check("kdf-calibrated-db-reopens", v != null && v.KdfIterations == tuning.Iterations, "stored KDBX parameters");
            v.Lock();
        }

        static void CoreIntegrityTests()
        {
            string official = Path.Combine(Paths.Root,"official-KeePass.exe");
            Version version;
            var signed = CoreLoader.ReadVerifiedCore(official, out version);
            Check("official-core-signature", signed.Length > 0 && version.ToString() == "2.61.1.0", "publisher + signed bytes");
            var unsigned = CoreLoader.Embedded();
            var path = Path.Combine(Paths.Root,"unsigned-core.dll"); File.WriteAllBytes(path,unsigned);
            using (var registry = Registry.CurrentUser.CreateSubKey(@"Software\WinUp\TrustedCore")) registry.SetValue(CoreLoader.Sha256(unsigned), "99.0.0 forged audit trust");
            bool rejected = false;
            try { CoreLoader.ReadVerifiedCore(path,out version); } catch (InvalidDataException) { rejected = true; }
            Check("forged-registry-trust-rejected", rejected, "unsigned real KeePassLib + forged HKCU hash");
            var tampered = (byte[])signed.Clone(); tampered[512] ^= 1;
            var badPath=Path.Combine(Paths.Root,"tampered-core.exe"); File.WriteAllBytes(badPath,tampered);
            rejected=false;
            try { CoreLoader.ReadVerifiedCore(badPath,out version); } catch (InvalidDataException) { rejected=true; }
            Check("tampered-signed-core-rejected", rejected, "signed executable modified after publication");
            string error;
            Check("official-package-stage", CoreUpdate.StageSignedPackage(File.ReadAllBytes(Path.Combine(Paths.Root,"official-KeePass.zip")), "2.61.1", out error), error ?? "signed portable package");
            var installedHash = CoreLoader.Sha256(File.ReadAllBytes(CoreLoader.CoreFile));
            byte[] fakeZip;
            using (var memory = new MemoryStream())
            {
                using (var archive = new ZipArchive(memory, ZipArchiveMode.Create, true))
                using (var output = archive.CreateEntry("KeePass.exe").Open()) output.Write(tampered,0,tampered.Length);
                fakeZip=memory.ToArray();
            }
            Check("tampered-update-preserves-core", !CoreUpdate.StageSignedPackage(fakeZip,"2.61.1",out error) &&
                installedHash == CoreLoader.Sha256(File.ReadAllBytes(CoreLoader.CoreFile)), "failed update leaves signed core intact");
        }
    }
}
