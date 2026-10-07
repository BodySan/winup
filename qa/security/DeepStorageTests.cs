using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace WinUp
{
    static partial class SecurityHarness
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CreateHardLink(string link, string existing, IntPtr security);

        static KeyValuePair<string, Action<System.IO.Stream>> DeepBatchWrite(string path, byte[] bytes)
        {
            return new KeyValuePair<string, Action<System.IO.Stream>>(path, stream => stream.Write(bytes, 0, bytes.Length));
        }

        static void DeepBatchFailure(string root, int failedIndex, bool newFirst, bool hadBackups)
        {
            string scenario = "batch-target-" + (failedIndex + 1) + "-" + (newFirst ? "new-first" : "existing") + (hadBackups ? "-backups" : "-no-backups");
            string directory = Path.Combine(root, scenario);
            Directory.CreateDirectory(directory);
            var paths = Enumerable.Range(0, 3).Select(i => Path.Combine(directory, "target" + i + ".dat")).ToArray();
            var previous = Enumerable.Range(0, 3).Select(i => Encoding.UTF8.GetBytes("SYNTHETIC-ORIGINAL-" + i)).ToArray();
            var backups = Enumerable.Range(0, 3).Select(i => Encoding.UTF8.GetBytes("SYNTHETIC-OLDER-BACKUP-" + i)).ToArray();
            for (int i = 0; i < paths.Length; ++i)
            {
                if (!newFirst || i != 0) File.WriteAllBytes(paths[i], previous[i]);
                if (hadBackups) File.WriteAllBytes(paths[i] + ".bak", backups[i]);
            }
            bool stopped = false;
            // Allow reading but deny DELETE: staging completes, and replacement
            // fails only after the preceding one or two commits really happened.
            using (var blocked = new FileStream(paths[failedIndex], FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                try { Paths.AtomicWriteBatch(paths.Select((path, i) => DeepBatchWrite(path, new byte[] { (byte)(90 + i) })).ToList()); }
                catch (IOException) { stopped = true; }
            }
            bool originalsMatch = paths.Select((path, i) => newFirst && i == 0 ? !File.Exists(path) : File.Exists(path) && File.ReadAllBytes(path).SequenceEqual(previous[i])).All(x => x);
            bool backupsMatch = paths.Select((path, i) => hadBackups ? File.Exists(path + ".bak") && File.ReadAllBytes(path + ".bak").SequenceEqual(backups[i]) : !File.Exists(path + ".bak")).All(x => x);
            Check(scenario + "-restores-all-targets", stopped && originalsMatch, "failure during second/third commit, including removal of a newly created target");
            Check(scenario + "-restores-previous-backups", stopped && backupsMatch, "both prior backup bytes and prior absence preserved");
            Check(scenario + "-cleans-temporaries", Directory.GetFiles(directory, "*.tmp").Length == 0, "staging and old-backup snapshots removed after successful rollback");
        }

        static void DeepBatchStorageTests(string root)
        {
            for (int target = 1; target <= 2; ++target)
            {
                DeepBatchFailure(root, target, false, true);
                DeepBatchFailure(root, target, true, true);
                DeepBatchFailure(root, target, false, false);
            }
            var directory = Path.Combine(root, "batch-serializer-fault");
            Directory.CreateDirectory(directory);
            var first = Path.Combine(directory, "first.dat");
            var second = Path.Combine(directory, "second.dat");
            var third = Path.Combine(directory, "third.dat");
            byte[] original = Encoding.UTF8.GetBytes("SYNTHETIC-STAGING-ORIGINAL");
            byte[] oldBackup = Encoding.UTF8.GetBytes("SYNTHETIC-STAGING-OLDER-BACKUP");
            foreach (var path in new[] { first, second, third }) { File.WriteAllBytes(path, original); File.WriteAllBytes(path + ".bak", oldBackup); }
            bool stopped = false;
            try
            {
                Paths.AtomicWriteBatch(new List<KeyValuePair<string, Action<System.IO.Stream>>> {
                    DeepBatchWrite(first, new byte[] { 1 }), DeepBatchWrite(second, new byte[] { 2 }),
                    new KeyValuePair<string, Action<System.IO.Stream>>(third, stream => { stream.WriteByte(3); throw new IOException("Synthetic third serializer fault"); }) });
            }
            catch (IOException) { stopped = true; }
            Check("batch-serializer-fault-does-not-start-commit", stopped && new[] { first, second, third }.All(path => File.ReadAllBytes(path).SequenceEqual(original) && File.ReadAllBytes(path + ".bak").SequenceEqual(oldBackup)), "all serializers run before replacements");
            Check("batch-serializer-fault-cleans-all-staging", Directory.GetFiles(directory, "*.tmp").Length == 0, "including the serializer that threw");
            Paths.AtomicWriteBatch(new[] { first, second, third }.Select(path => DeepBatchWrite(path, new byte[] { 7, 8, 9 })).ToList());
            Check("batch-success-keeps-one-previous-version", new[] { first, second, third }.All(path => File.ReadAllBytes(path).SequenceEqual(new byte[] { 7, 8, 9 }) && File.ReadAllBytes(path + ".bak").SequenceEqual(original)), "successful save publishes all targets and their immediate prior versions");
            stopped = false;
            try { Paths.AtomicWriteBatch(new List<KeyValuePair<string, Action<System.IO.Stream>>> { DeepBatchWrite(first, new byte[] { 4 }), DeepBatchWrite(first + ".bak", new byte[] { 5 }) }); }
            catch (IOException) { stopped = true; }
            Check("batch-backup-target-alias-refused-before-write", stopped && File.ReadAllBytes(first).SequenceEqual(new byte[] { 7, 8, 9 }) && File.ReadAllBytes(first + ".bak").SequenceEqual(original), "one target cannot replace another target's rollback copy");
            var remnant = first + "." + Guid.NewGuid().ToString("N") + ".tmp";
            var foreign = first + ".unrelated.tmp";
            File.WriteAllBytes(remnant, original); File.WriteAllBytes(foreign, original);
            Check("atomic-remnants-recognize-guid-and-preserve-other-names", Paths.AtomicRemnants(first).Contains(remnant) && !Paths.AtomicRemnants(first).Contains(foreign), "rotation cleanup covers batch snapshots without a broad wildcard deletion");
            File.Delete(remnant); File.Delete(foreign);
        }

        static void DeepBackupStorageTests(string root)
        {
            var directory = Path.Combine(root, "strict-backups");
            Directory.CreateDirectory(directory);
            var source = Path.Combine(root, "synthetic-backup-source.dat");
            var contents = Encoding.UTF8.GetBytes("SYNTHETIC-ENCRYPTED-COPY-FIXTURE");
            File.WriteAllBytes(source, contents);
            string[] foreign = { "fixture-personal.dat", "fixture-29991340-999999-999-aabbccdd.dat", "fixture-20261007-120000-000-aabbccddee.dat", "fixture-20261007-120000-000.data", "fixture-20261007-120000-000-extra.dat" };
            foreach (string name in foreign) File.WriteAllBytes(Path.Combine(directory, name), contents);
            var future = Path.Combine(directory, "fixture-29990101-120000-000-aabbccdd.dat");
            var legacy = Path.Combine(directory, "fixture-20200101-120000-000.dat");
            File.WriteAllBytes(future, contents); File.WriteAllBytes(legacy, contents);
            Check("backup-strict-name-accepts-supported-formats", Backup.IsBackupName(future, "fixture", ".dat") && Backup.IsBackupName(legacy, "fixture", ".dat") && foreign.All(name => !Backup.IsBackupName(name, "fixture", ".dat")), "exact valid date plus optional eight hexadecimal characters");
            string previousError = Backup.LastError;
            try
            {
                Backup.Copy(source, "fixture", ".dat", new Settings { BackupDir = directory, BackupKeep = 1 });
                var own = Directory.GetFiles(directory).Where(path => Backup.IsBackupName(path, "fixture", ".dat")).ToArray();
                Check("backup-retention-pins-new-copy-even-with-future-file", Backup.LastError == null && own.Length == 1 && own[0] != future && File.ReadAllBytes(own[0]).SequenceEqual(contents), "keep one always retains the copy just completed");
                Check("backup-retention-preserves-unrelated-files", foreign.All(name => File.ReadAllBytes(Path.Combine(directory, name)).SequenceEqual(contents)), "prefix alone does not authorize deleting user files");
            }
            finally { Backup.LastError = previousError; }
        }
        [DllImport("user32.dll", EntryPoint="SendMessageW")]
        static extern IntPtr SendSessionLock(IntPtr window, int message, IntPtr parameter, IntPtr data);

        static void DeepStorageTests()
        {
            var root = Path.Combine(Paths.Root, "deep-storage");
            Directory.CreateDirectory(root);
            DeepBatchStorageTests(root);
            DeepBackupStorageTests(root);
            Ui(delegate {
                Lock();
                int generation = form.BrowserGeneration;
                SendSessionLock(form.Handle, Win.WmWtsSessionChange, new IntPtr(Win.WtsSessionLock), IntPtr.Zero);
                Check("windows-session-lock-cancels-pending-unlock", form.VaultNow == null && form.BrowserGeneration > generation, "actual WM_WTSSESSION_CHANGE while vault is still null");
            });
            var path = Path.Combine(root, "atomic.dat");
            byte[] original = Encoding.UTF8.GetBytes("SYNTHETIC-ORIGINAL-ATOMIC");
            Paths.AtomicWrite(path, original);
            bool stopped = false;
            try { Paths.AtomicWriteStream(path, stream => { stream.WriteByte(42); throw new IOException("Synthetic mid-write fault"); }); }
            catch (IOException) { stopped = true; }
            Check("atomic-mid-write-keeps-original", stopped && File.ReadAllBytes(path).SequenceEqual(original), "fault before commit");
            Check("atomic-fault-removes-temporary", Directory.GetFiles(root, "atomic.dat.*.tmp").Length == 0, "only this operation's temporary file");

            // A fixed-name .tmp planted by another process is never opened.
            var victim = Path.Combine(root, "victim.dat");
            File.WriteAllBytes(victim, original);
            var planted = path + ".tmp";
            if (File.Exists(planted)) File.Delete(planted);
            Check("atomic-planted-hardlink-fixture", CreateHardLink(planted, victim, IntPtr.Zero), "synthetic NTFS hard link");
            Paths.AtomicWrite(path, new byte[] { 1, 2, 3 });
            Check("atomic-planted-temporary-does-not-touch-victim", File.ReadAllBytes(victim).SequenceEqual(original), "random CreateNew temporary name");
            File.Delete(planted);

            var values = Enumerable.Range(0, 12).Select(i => Enumerable.Repeat((byte)(i + 1), 8192 + i).ToArray()).ToArray();
            Task.WaitAll(values.Select(value => Task.Run(() => Paths.AtomicWrite(path, value))).ToArray());
            Check("atomic-concurrent-writers-complete", values.Any(value => value.SequenceEqual(File.ReadAllBytes(path))), "twelve concurrent saves; one complete result");
            Check("atomic-concurrent-writers-no-temporary", Directory.GetFiles(root, "atomic.dat.*.tmp").Length == 0, "no stale operation files");
            var before = File.ReadAllBytes(path);
            using (var lockedBackup = new FileStream(path + ".bak", FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                stopped = false;
                try { Paths.AtomicWrite(path, new byte[] { 99 }); } catch (IOException) { stopped = true; }
                Check("atomic-locked-backup-keeps-original", stopped && File.ReadAllBytes(path).SequenceEqual(before), "commit failure including retry");
            }

            string error;
            var hard = Path.Combine(root, "wipe-hard.dat");
            Check("wipe-hardlink-fixture", CreateHardLink(hard, victim, IntPtr.Zero), "two names refer to one object");
            Check("wipe-hardlink-rejected-without-damage", !Secure.WipeFile(hard, out error) && File.ReadAllBytes(victim).SequenceEqual(original), "refuse overwrite of multiply linked object");
            File.Delete(hard);
            var disposable = Path.Combine(root, "wipe-normal.dat");
            File.WriteAllBytes(disposable, original);
            Check("wipe-normal-deletes-verified-file", Secure.WipeFile(disposable, out error) && !File.Exists(disposable), "overwrite and deletion use the same handle");

            Ui(delegate { NewVault(false); form.VaultNow.Save(); });
            var databaseBefore = File.ReadAllBytes(KdbxStore.KdbxFile);
            using (var lockedBackup = new FileStream(KdbxStore.KdbxFile + ".bak", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
            {
                stopped = false;
                try { form.VaultNow.Save(); } catch (IOException) { stopped = true; }
                Check("kdbx-failed-commit-preserves-encrypted-database", stopped && File.ReadAllBytes(KdbxStore.KdbxFile).SequenceEqual(databaseBefore), "serializer uses atomic commit");
            }
            int left; StoreResult status;
            var reopened = KdbxStore.Open(Password, null, out left, out status);
            Check("kdbx-after-failed-save-reopens", reopened != null && status == StoreResult.Ok && SecretMatches(reopened.Entries[0], "Audit-only-secret!"), "original password and contents");
            if (reopened != null) reopened.Lock();
            Ui(Lock);
            var oversizedKey = Path.Combine(root, "oversized.key");
            using (var stream = File.Create(oversizedKey)) stream.SetLength(4 * 1024 * 1024 + 1);
            stopped = false;
            try { KdbxStore.Create(Password, oversizedKey); } catch (InvalidDataException) { stopped = true; }
            Check("keyfile-size-rejected-before-allocation", stopped, "file length checked while held open");
            var savedApps = File.Exists(Paths.AppsFile) ? File.ReadAllBytes(Paths.AppsFile) : null;
            try
            {
                File.WriteAllText(Paths.AppsFile, "{\"Apps\":[null],\"Links\":[null],\"Templates\":[null],\"Winget\":[null],\"Settings\":{\"DefaultsVersion\":2147483647,\"AutoLockMinutes\":-1,\"BackupKeep\":2147483647}}", Encoding.UTF8);
                var settings = AppStore.Load(true);
                Check("malformed-settings-null-records-do-not-crash", settings.Apps.Count == 0 && settings.Links.Count == 0 && settings.Templates.Count == 0 && settings.Winget.Count == 0, "null array records filtered before display and merge");
                Check("malformed-settings-values-bounded", settings.Settings.AutoLockMinutes == 1 && settings.Settings.BackupKeep == 1000, "invalid timeout and retention cannot disable limits");
                File.WriteAllText(Paths.AppsFile, "null", Encoding.UTF8);
                stopped = false;
                try { AppStore.Load(true); } catch (InvalidDataException) { stopped = true; }
                Check("malformed-settings-null-root-refused", stopped, "explicit recoverable format error");
            }
            finally { if (savedApps != null) File.WriteAllBytes(Paths.AppsFile, savedApps); else File.Delete(Paths.AppsFile); AppStore.ChangedOutside = null; }
        }
    }
}
