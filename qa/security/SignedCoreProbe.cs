using System;
using System.IO;
using System.Reflection;
using KeePassLib;
using KeePassLib.Keys;
using KeePassLib.Serialization;

static class SignedCoreProbe
{
    static int Main()
    {
        if (!AppDomain.CurrentDomain.BaseDirectory.StartsWith(@"C:\WinUpAudit\", StringComparison.OrdinalIgnoreCase)) return 2;
        AppDomain.CurrentDomain.AssemblyResolve += (s, e) => new AssemblyName(e.Name).Name == "KeePassLib"
            ? Assembly.Load(File.ReadAllBytes(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "signed-core.exe"))) : null;
        return Test();
    }
    static int Test()
    {
        Console.WriteLine(typeof(PwDatabase).Assembly.FullName);
        var key = new CompositeKey(); key.AddUserKey(new KcpPassword("synthetic-signed-core-check"));
        var db = new PwDatabase();
        string file = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "signed-test.kdbx");
        db.New(IOConnectionInfo.FromPath(file), key); db.Save(null); db.Close();
        db.Open(IOConnectionInfo.FromPath(file), key, null); db.Close();
        Console.WriteLine("PASS signed-core-roundtrip");
        return 0;
    }
}
