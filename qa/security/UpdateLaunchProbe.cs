using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;

// A harmless marker executable is planted in an isolated installer directory.
// This probe is deliberately restricted to Windows Sandbox test roots.
internal static class UpdateLaunchProbe {
    static readonly string Root = @"C:\WinUpAudit\UpdateLaunchProof";
    static int Main(string[] args) {
        string own = Assembly.GetExecutingAssembly().Location;
        if(!own.StartsWith(@"C:\WinUpAudit\",StringComparison.OrdinalIgnoreCase)) return 90;
        Directory.CreateDirectory(Root);
        string marker = Path.Combine(Root,"planted-executed.txt");
        if(Path.GetFileName(own).Equals("msiexec.exe",StringComparison.OrdinalIgnoreCase)) {
            File.WriteAllText(marker,"synthetic executable selected instead of the Windows installer");
            return 0;
        }
        if(args.Length!=1 || !Path.GetFullPath(args[0]).StartsWith(@"C:\WinUpAudit\",StringComparison.OrdinalIgnoreCase))return 91;
        string planted=Path.Combine(Root,"installer");Directory.CreateDirectory(planted);
        File.Copy(own,Path.Combine(planted,"msiexec.exe"),true);
        string dummy=Path.Combine(planted,"dummy.msi");File.WriteAllText(dummy,"synthetic invalid MSI");
        if(File.Exists(marker))File.Delete(marker);
        using(var process=Process.Start(new ProcessStartInfo("msiexec.exe","/i \""+dummy+"\" /qn /norestart") {UseShellExecute=true,WorkingDirectory=planted,WindowStyle=ProcessWindowStyle.Hidden})) {
            if(!process.WaitForExit(15000)) {process.Kill();return 92;}
        }
        bool oldSelected=File.Exists(marker);Console.WriteLine("unqualified_planted_selected="+oldSelected);
        if(File.Exists(marker))File.Delete(marker);
        var assembly=Assembly.LoadFrom(args[0]);
        var method=assembly.GetType("WinUp.InstallForm").GetMethod("SystemTool",BindingFlags.Static|BindingFlags.NonPublic);
        string safe=(string)method.Invoke(null,new object[]{"msiexec.exe"});
        using(var process=Process.Start(new ProcessStartInfo(safe,"/i \""+dummy+"\" /qn /norestart") {UseShellExecute=true,WorkingDirectory=planted,WindowStyle=ProcessWindowStyle.Hidden})) {
            if(!process.WaitForExit(15000)) {process.Kill();return 93;}
            Console.WriteLine("fixed_system_installer_exit="+process.ExitCode);
        }
        bool fixedSelected=File.Exists(marker);Console.WriteLine("fixed_planted_selected="+fixedSelected);
        File.WriteAllText(Path.Combine(Root,"proof.txt"),"unqualified_planted_selected="+oldSelected+Environment.NewLine+"fixed_planted_selected="+fixedSelected);
        return oldSelected && !fixedSelected ? 0 : 1;
    }
}
