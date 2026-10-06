using System;
using WinUp;
class CoreNetworkProbe
{
    static int Main()
    {
        if (!AppDomain.CurrentDomain.BaseDirectory.StartsWith(@"C:\WinUpAudit\", StringComparison.OrdinalIgnoreCase)) return 2;
        string error;
        bool ok = CoreUpdate.DownloadAndStage("2.61.1", Console.WriteLine, out error);
        Console.WriteLine(ok ? "PASS online-signed-core-update" : "ONLINE-ERROR " + error);
        return ok ? 0 : 1;
    }
}
