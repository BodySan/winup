// Stable public API: the identical scenario runs against deployed and candidate WinUp.
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using WinUp;

static class MemoryScenario
{
    static KdbxStore vault;
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool WriteFile(IntPtr file, byte[] buffer, int count, out int written, IntPtr overlapped);

    static string MakeMarker()
    {
        var bytes = new byte[40]; var chars = new char[40];
        try
        {
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(bytes);
            for (int i = 0; i < chars.Length; i++) chars[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[bytes[i] & 31];
            return new string(chars);
        }
        finally { Array.Clear(bytes, 0, bytes.Length); Array.Clear(chars, 0, chars.Length); }
    }
    static void Wipe(string text)
    { unsafe { fixed (char* pointer = text) for (int i = 0; i < text.Length; i++) pointer[i] = '\0'; } }
    static byte[] Row(string text)
    {
        var result = new byte[text.Length + 1];
        for (int i = 0; i < text.Length; i++) result[i] = (byte)text[i];
        result[text.Length] = 10;
        return result;
    }
    static int Main()
    {
        if (!AppDomain.CurrentDomain.BaseDirectory.StartsWith(@"C:\WinUpAudit\", StringComparison.OrdinalIgnoreCase)) return 2;
        AppDomain.CurrentDomain.AssemblyResolve += (s, e) => new AssemblyName(e.Name).Name == "KeePassLib" ? CoreLoader.Resolve() : null;
        Prepare();
        // Idle after callers released temporary data. The retained store remains alive.
        GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
        int opened = Scan("open");
        vault.Lock();
        GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
        int locked = Scan("locked");
        Console.WriteLine("RESULT open=" + opened + " locked=" + locked);
        return 0;
    }
    static void Prepare()
    {
        Directory.CreateDirectory(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "data"));
        string master = MakeMarker(), password = MakeMarker(), otp = MakeMarker();
        bool storeOwnsPassword = false, storeOwnsOtp = false;
        byte[][] rows = new byte[4][];
        string recovery = null, normalizedRecovery = null;
        try
        {
            vault = KdbxStore.Create(master, null);
            recovery = vault.MakeRecoveryCode(); normalizedRecovery = Vault.NormalizeCode(recovery);
            rows[0] = Row(master); rows[1] = Row(password); rows[2] = Row(otp); rows[3] = Row(normalizedRecovery);
            using (var file = new FileStream(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "markers.txt"), FileMode.Create, FileAccess.Write, FileShare.Read, 1))
                foreach (var row in rows)
                {
                    int written;
                    if (!WriteFile(file.SafeFileHandle.DangerousGetHandle(), row, row.Length, out written, IntPtr.Zero) || written != row.Length) throw new IOException("Marker write failed");
                }
            vault.Entries.Add(new LoginEntry { Id = "memory-entry", Name = "Synthetic memory check", Password = password });
            vault.Otp.Add(new OtpEntry { Id = "memory-otp", Secret = otp });
            var retainedPassword = vault.Entries[0].Password;
            var retainedOtp = vault.Otp[0].Secret;
            storeOwnsPassword = ReferenceEquals(retainedPassword, password);
            storeOwnsOtp = ReferenceEquals(retainedOtp, otp);
            if (!storeOwnsPassword) Wipe(retainedPassword);
            if (!storeOwnsOtp) Wipe(retainedOtp);
            vault.Save();
            vault.Lock();
            int left; StoreResult status;
            vault = KdbxStore.Open(master, null, out left, out status);
            if (vault == null) throw new InvalidOperationException("Memory scenario could not reopen its database");
        }
        finally
        {
            Wipe(master);
            if (recovery != null) Wipe(recovery);
            if (normalizedRecovery != null) Wipe(normalizedRecovery);
            if (!storeOwnsPassword) Wipe(password);
            if (!storeOwnsOtp) Wipe(otp);
            foreach (var row in rows) if (row != null) Array.Clear(row, 0, row.Length);
        }
    }
    static int Scan(string phase)
    {
        string root = AppDomain.CurrentDomain.BaseDirectory;
        var info = new ProcessStartInfo(Path.Combine(root, "MemoryProbe.exe"), "--scan " + Process.GetCurrentProcess().Id + " " + Path.Combine(root, "markers.txt"))
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true };
        using (var process = Process.Start(info))
        {
            var output = process.StandardOutput.ReadToEndAsync();
            if (!process.WaitForExit(30000)) { process.Kill(); throw new TimeoutException("Memory scan timed out"); }
            Console.WriteLine(phase + ": " + output.Result.Trim());
            return process.ExitCode;
        }
    }
}
