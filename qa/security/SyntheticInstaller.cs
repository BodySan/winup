using System;
using System.IO;
using System.Threading;

static class SyntheticInstaller {
    static int Main(string[] args) {
        string folder=AppDomain.CurrentDomain.BaseDirectory;
        if(!folder.StartsWith(@"C:\WinUpAudit\",StringComparison.OrdinalIgnoreCase))return 99;
        if(args.Length!=1)return 98;
        int code;if(!int.TryParse(args[0],out code))return 97;
        File.WriteAllText(Path.Combine(folder,"synthetic-installer-"+code+".txt"),"started");
        if(code==-1)Thread.Sleep(30000);
        return code;
    }
}
