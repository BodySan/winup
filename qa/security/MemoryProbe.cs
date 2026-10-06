// Reads known synthetic buffers or scans for lab-generated markers in Sandbox.
// Only SecurityHarness under C:\WinUpAudit; no dumps or secret values in output.
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;

static class MemoryProbe
{
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] data, IntPtr size, out IntPtr read);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] static extern IntPtr VirtualQueryEx(IntPtr process, IntPtr address, out Region region, IntPtr size);
    [StructLayout(LayoutKind.Sequential)]
    struct Region
    {
        public IntPtr Base, Allocation;
        public uint AllocationProtection;
        public IntPtr Size;
        public uint State, Protection, Type;
    }

    static int Scan(int pid, string markerFile)
    {
        using (var target = Process.GetProcessById(pid))
        {
            var path = target.MainModule.FileName;
            if (!path.StartsWith(@"C:\WinUpAudit\", StringComparison.OrdinalIgnoreCase) || Path.GetFileName(path) != "SecurityHarness.exe") return 2;
        }
        if (!Path.GetFullPath(markerFile).StartsWith(@"C:\WinUpAudit\", StringComparison.OrdinalIgnoreCase)) return 2;
        var patterns = new List<byte[]>();
        foreach (string marker in File.ReadAllLines(markerFile))
        {
            if (marker.Length < 24 || marker.Length > 128) return 2;
            patterns.Add(Encoding.UTF8.GetBytes(marker)); patterns.Add(Encoding.Unicode.GetBytes(marker));
        }
        int[] hits = new int[patterns.Count];
        var handle = OpenProcess(0x410, false, pid);
        if (handle == IntPtr.Zero) return 3;
        long scanned = 0, address = 0;
        try
        {
            Region region;
            while (VirtualQueryEx(handle, new IntPtr(address), out region, new IntPtr(Marshal.SizeOf(typeof(Region)))) != IntPtr.Zero)
            {
                long start = region.Base.ToInt64(), size = region.Size.ToInt64();
                if (size <= 0 || start + size <= address) return 3;
                if (region.State == 0x1000 && (region.Protection & 0x101) == 0)
                {
                    for (long offset = 0; offset < size; offset += 1024 * 1024)
                    {
                        int length = (int)Math.Min(1024 * 1024 + 256, size - offset);
                        var buffer = new byte[length]; IntPtr read;
                        ReadProcessMemory(handle, new IntPtr(start + offset), buffer, new IntPtr(length), out read);
                        int valid = (int)read.ToInt64();
                        scanned += valid;
                        if (scanned > 768L * 1024 * 1024) return 4;
                        for (int p = 0; p < patterns.Count; p++)
                        {
                            byte[] needle = patterns[p];
                            for (int at = 0; at <= valid - needle.Length; at++)
                            {
                                if (buffer[at] != needle[0]) continue;
                                int i = 1; while (i < needle.Length && buffer[at + i] == needle[i]) i++;
                                if (i == needle.Length) hits[p]++;
                            }
                        }
                        Array.Clear(buffer, 0, buffer.Length);
                    }
                }
                address = start + size;
            }
            int total = 0;
            for (int i = 0; i < hits.Length; i += 2)
            { Console.WriteLine("marker" + (i / 2) + " utf8=" + hits[i] + " utf16=" + hits[i + 1]); total += hits[i] + hits[i + 1]; }
            Console.WriteLine("scanned-bytes=" + scanned);
            return total == 0 ? 0 : 1;
        }
        finally { foreach (var pattern in patterns) Array.Clear(pattern, 0, pattern.Length); CloseHandle(handle); }
    }

    static int Main(string[] args)
    {
        if (args.Length == 3 && args[0] == "--scan") return Scan(int.Parse(args[1]), args[2]);
        if (args.Length != 4) return 2;
        int pid = int.Parse(args[0]), length = int.Parse(args[2]);
        using (var target = Process.GetProcessById(pid))
        {
            string path = target.MainModule.FileName;
            if (!path.StartsWith(@"C:\WinUpAudit\", StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(Path.GetFileName(path), "SecurityHarness.exe", StringComparison.OrdinalIgnoreCase) ||
                length < 1 || length > 1024) return 2;
        }
        IntPtr handle = OpenProcess(0x10 /* VM_READ */, false, pid);
        if (handle == IntPtr.Zero) return 3;
        byte[] data = new byte[length];
        try
        {
            IntPtr read;
            if (!ReadProcessMemory(handle, new IntPtr(long.Parse(args[1])), data, new IntPtr(length), out read) || read.ToInt64() != length) return 3;
            using (var sha = SHA256.Create())
            {
                string hash = BitConverter.ToString(sha.ComputeHash(data)).Replace("-", "");
                return string.Equals(hash, args[3], StringComparison.Ordinal) ? 0 : 1;
            }
        }
        finally { Array.Clear(data, 0, data.Length); CloseHandle(handle); }
    }
}
