using System;
using System.IO;
using System.Diagnostics;
using System.Reflection;
using System.Text;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
namespace WinUp {
    static class FollowupSecurityProbe {
        static int passed,failed;
        static void Check(string name,bool ok){Console.WriteLine((ok?"PASS ":"FAIL ")+name);if(ok)passed++;else failed++;}
        static bool Reject(Action action){try{action();return false;}catch{return true;}}
        [STAThread]static int Main(string[] args){
            if(!Paths.Root.StartsWith(@"C:\WinUpAudit\",StringComparison.OrdinalIgnoreCase)||(Environment.UserName!="WDAGUtilityAccount"&&Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true"))throw new Exception("Disposable Windows Sandbox or CI only");
            AppDomain.CurrentDomain.AssemblyResolve+=(s,e)=>new AssemblyName(e.Name).Name=="KeePassLib"?CoreLoader.Resolve():EmbeddedModules.Resolve(e.Name);
            Console.OutputEncoding=new UTF8Encoding(false);
            if(Array.IndexOf(args,"--install")>=0){try{var permission=InstallAuthorization.Receive(args);File.WriteAllText(Path.Combine(Paths.Root,"elevated-permission.json"),new JavaScriptSerializer().Serialize(permission));return 0;}catch{return 2;}}
            if(args.Length==1&&args[0]=="--web-public"){
                bool ok=false;foreach(string url in new[]{"https://keepass.info/","https://www.microsoft.com/"}){string result=AccountAddressReview.CheckWeb(url,CancellationToken.None);Console.WriteLine(url+" "+result);ok|=result.StartsWith("HTTP ",StringComparison.Ordinal);}return ok?0:1;
            }
            if(args.Length==5&&args[0]=="--authorization-client"){
                try{var permission=InstallAuthorization.Receive(args[1],int.Parse(args[2]),long.Parse(args[3]));File.WriteAllText(args[4],new JavaScriptSerializer().Serialize(permission));return 0;}catch(Exception ex){Console.WriteLine("REJECT "+ex.Message);return 2;}
            }
            try{Arguments();Authorization();Addresses();PlatformStrings();}catch(Exception ex){Check("unhandled-"+ex,false);}
            Console.WriteLine("RESULT passed="+passed+" failed="+failed);return failed==0?0:1;
        }
        static void Arguments(){
            Directory.CreateDirectory(Paths.Apps);
            string batch=Path.Combine(Paths.Apps,"fixture.cmd"),marker=Path.Combine(Paths.Root,"injected.txt");
            File.WriteAllText(batch,"@echo off\r\necho %1>\"%~dp0accepted.txt\"\r\nexit 0\r\n");
            var item=new AppItem{File=batch,Args="safe & echo injected>\""+marker+"\" & exit"};
            Check("batch-argument-command-boundary",Reject(()=>MainForm.LaunchInfo(item))&&!File.Exists(marker));
            foreach(var value in new[]{"x|echo","x>file","%COMSPEC%","!PATH!","x^y","(echo x)","x\r\necho"})Check("batch-reject-"+value.Replace("\r"," ").Replace("\n"," "),Reject(()=>ProcessArguments.Script(batch,value)));
            Check("batch-unclosed-quote",Reject(()=>ProcessArguments.Script(batch,"\"unfinished")));
            Check("batch-expanded-path-rejected",Reject(()=>ProcessArguments.Script(Path.Combine(Paths.Apps,"%TEMP%.cmd"),"")));
            string[] values={"", "hello world", "кириллица", "C:\\space dir\\", "literal\"quote", "one\\\"two"};
            Check("windows-argument-roundtrip",ProcessArguments.Parse(ProcessArguments.Join(values)).SequenceEqual(values));
            item.Args="\"hello world\"";var info=MainForm.LaunchInfo(item);info.UseShellExecute=false;info.CreateNoWindow=true;
            using(var process=Process.Start(info)){Check("batch-positive-exits",process.WaitForExit(5000)&&process.ExitCode==0);if(!process.HasExited)process.Kill();}
            Check("batch-positive-space-argument",File.ReadAllText(Path.Combine(Paths.Apps,"accepted.txt")).Trim()=="\"hello world\"");
            Check("batch-system-interpreter",Path.GetDirectoryName(info.FileName)==Environment.GetFolderPath(Environment.SpecialFolder.System));
            string named=Path.Combine(Paths.Apps,"folder (x86) & name");Directory.CreateDirectory(named);string namedBatch=Path.Combine(named,"fixture.cmd");File.Copy(batch,namedBatch);
            var namedInfo=ProcessArguments.Script(namedBatch,"safe");namedInfo.UseShellExecute=false;namedInfo.CreateNoWindow=true;
            using(var process=Process.Start(namedInfo)){Check("batch-path-spaces-parentheses-ampersand",process.WaitForExit(5000)&&process.ExitCode==0&&File.Exists(Path.Combine(named,"accepted.txt")));if(!process.HasExited)process.Kill();}
            var ps=ProcessArguments.Script(Path.Combine(Paths.Apps,"fixture.ps1"),"-Name \"hello world\" -Value \"literal&value\"");
            Check("powershell-file-arguments",ps.Arguments.Contains("\"hello world\"")&&ps.Arguments.Contains("\"literal&value\"")&&Path.IsPathRooted(ps.FileName));
            File.WriteAllText(Path.Combine(Paths.Apps,"fixture.ps1"),"param([string]$Name,[string]$Value)\r\n[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'ps-accepted.txt'),$Name+'|'+$Value)\r\nexit 0\r\n");
            ps.UseShellExecute=false;ps.CreateNoWindow=true;using(var process=Process.Start(ps)){Check("powershell-script-executed",SpinWait.SpinUntil(()=>File.Exists(Path.Combine(Paths.Apps,"ps-accepted.txt")),10000));if(!process.HasExited)process.Kill();}
            Check("powershell-actual-values",File.ReadAllText(Path.Combine(Paths.Apps,"ps-accepted.txt"))=="hello world|literal&value");
            Check("install-batch-rejects-command-arguments",Reject(()=>InstallForm.LaunchInfo(batch,item.Args+" & echo injected")));
            var installBatch=InstallForm.LaunchInfo(batch,"safe");installBatch.UseShellExecute=false;installBatch.CreateNoWindow=true;
            using(var process=Process.Start(installBatch)){Check("install-batch-completes-without-open-console",process.WaitForExit(5000)&&process.ExitCode==0);if(!process.HasExited)process.Kill();}
            var installPs=InstallForm.LaunchInfo(Path.Combine(Paths.Apps,"fixture.ps1"),"-Name \"hello world\" -Value \"literal&value\"");installPs.UseShellExecute=false;installPs.CreateNoWindow=true;
            using(var process=Process.Start(installPs)){Check("install-powershell-completes-without-open-console",process.WaitForExit(10000)&&process.ExitCode==0);if(!process.HasExited)process.Kill();}
        }
        static AuthorizedInstallation Permission(){return new AuthorizedInstallation{schema=1,silent=true,items=new[]{new AppItem{Id="fixture",Name="Учебный установщик",File=Path.Combine(Paths.Apps,"fixture.exe"),Args="/quiet"}}};}
        static void Authorization(){
            Check("install-reject-hash-only",Reject(()=>InstallAuthorization.Receive(new[]{"--install","fixture","--apps-sha256",new string('a',64)})));
            Check("install-invalid-request",Reject(()=>InstallAuthorization.Validate(new AuthorizedInstallation{schema=1,items=new AppItem[0]})));
            var malformed=Permission();malformed.items[0].File="relative.exe";Check("install-relative-file-rejected",Reject(()=>InstallAuthorization.Validate(malformed)));
            int pid=Process.GetCurrentProcess().Id;long started=Process.GetCurrentProcess().StartTime.ToUniversalTime().ToFileTimeUtc();
            Check("process-live-identity",InstallAuthorization.SameProcess(pid,started,Assembly.GetExecutingAssembly().Location));
            Check("process-start-time-mismatch",!InstallAuthorization.SameProcess(pid,started+1,Assembly.GetExecutingAssembly().Location));
            Check("process-absent-rejected",!InstallAuthorization.SameProcess(-1,started,Assembly.GetExecutingAssembly().Location));
            foreach(bool foreign in new[]{false,true}){
                var permission=Permission();string output=Path.Combine(Paths.Root,"permission-"+foreign+".json");
                using(var session=new InstallAuthorization.Session(permission)){
                    permission.items[0].Args="changed-after-consent";
                    Task delivery=session.Serve();string exe=Assembly.GetExecutingAssembly().Location;
                    if(foreign){string copy=Path.Combine(Paths.Root,"ForeignClient.exe");File.Copy(exe,copy,true);exe=copy;}
                    string arguments="--authorization-client "+session.Name+" "+session.Owner+" "+session.Started+" "+ProcessArguments.Quote(output);
                    var start=new ProcessStartInfo(exe,arguments){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
                    using(var child=Process.Start(start)){
                        session.Bind(child);bool sent=true;try{if(!delivery.Wait(10000))throw new Exception("Delivery timed out");}catch(Exception ex){Console.WriteLine("DELIVERY "+ex);sent=false;}
                        if(!child.WaitForExit(10000)){child.Kill();Check("install-child-timeout",false);}
                        Console.WriteLine("CLIENT "+child.StandardOutput.ReadToEnd()+child.StandardError.ReadToEnd());
                        if(foreign)Check("install-foreign-process-rejected",!sent&&!File.Exists(output));
                        else{Check("install-exact-child-allowed",sent&&child.ExitCode==0&&File.Exists(output));if(File.Exists(output)){var result=new JavaScriptSerializer().Deserialize<AuthorizedInstallation>(File.ReadAllText(output));Check("install-selection-immutable",result.items[0].Args=="/quiet"&&result.silent);}}
                    }
                }
            }
            using(var session=new InstallAuthorization.Session(Permission())){
                var delivery=session.Serve();session.Dispose();Check("install-cancel-releases-server",Reject(()=>delivery.GetAwaiter().GetResult()));
                Check("install-cancelled-permission-rejected",Reject(()=>InstallAuthorization.Receive(session.Name,session.Owner,session.Started)));
            }
            if(Environment.UserName=="WDAGUtilityAccount"&&Win.IsAdmin()){
                string output=Path.Combine(Paths.Root,"elevated-permission.json");InstallAuthorization.Launch(Permission().items,true).GetAwaiter().GetResult();
                Check("install-real-runas-broker",SpinWait.SpinUntil(()=>File.Exists(output),5000));
            }
        }
        static void Addresses(){
            foreach(var text in new[]{"0.0.0.0","127.0.0.1","10.0.0.1","172.16.0.1","192.168.1.1","169.254.169.254","100.64.1.1","198.18.1.1","192.0.2.1","198.51.100.1","203.0.113.1","224.0.0.1","255.255.255.255","::1","::","fc00::1","fe80::1","ff02::1","::ffff:127.0.0.1","2002:7f00:1::","2001:db8::1","64:ff9b::7f00:1"})Check("address-private-rejected-"+text,!PublicWebProbe.IsPublic(IPAddress.Parse(text)));
            foreach(var text in new[]{"1.1.1.1","8.8.8.8","2606:4700:4700::1111"})Check("address-public-allowed-"+text,PublicWebProbe.IsPublic(IPAddress.Parse(text)));
            Check("address-mixed-dns-rejected",!PublicWebProbe.PublicSet(new[]{IPAddress.Parse("1.1.1.1"),IPAddress.Loopback}));
            Check("address-empty-dns-rejected",!PublicWebProbe.PublicSet(new IPAddress[0]));
            var listener=new System.Net.Sockets.TcpListener(IPAddress.Loopback,0);listener.Start();int port=((IPEndPoint)listener.LocalEndpoint).Port;
            try{foreach(var host in new[]{"localhost","127.0.0.1","2130706433"}){string result=AccountAddressReview.CheckWeb("https://"+host+":"+port+"/test",CancellationToken.None);Check("address-no-loopback-connection-"+host,result.Contains("адрес")&&!listener.Pending());}}
            finally{listener.Stop();}
            Check("address-userinfo-rejected",AccountAddressReview.CheckWeb("https://user:pass@example.com",CancellationToken.None).Contains("без данных"));
            Check("address-http-rejected",AccountAddressReview.CheckWeb("http://example.com",CancellationToken.None).Contains("HTTPS"));
            var cancelled=new CancellationTokenSource();cancelled.Cancel();Check("address-cancellation",AccountAddressReview.CheckWeb("https://example.com",cancelled.Token).Contains("отменена"));
            Check("website-shell-protocol-rejected",Reject(()=>BrowserPages.SiteLaunch("file:///C:/Windows/System32/calc.exe",null)));
        }
        static unsafe void PlatformStrings(){
            Check("platform-text-null",WinUpPluginAuthenticator.Text(null)=="");
            var text="hello\0ignored".ToCharArray();fixed(char* p=text)Check("platform-text-null-terminator",WinUpPluginAuthenticator.Text(p)=="hello");
            var maximum=(new string('x',4096)+"\0").ToCharArray();fixed(char* p=maximum)Check("platform-text-maximum",WinUpPluginAuthenticator.Text(p).Length==4096);
            var oversized=(new string('x',5000)+"\0").ToCharArray();fixed(char* p=oversized){bool rejected=false;try{WinUpPluginAuthenticator.Text(p);}catch(IOException){rejected=true;}Check("platform-text-bounded-before-allocation",rejected);}
            Check("platform-client-foreign-process",!SystemPasskeyProvider.IsClient(Process.GetCurrentProcess().Id));
            Directory.CreateDirectory(SystemPasskeySetup.Folder);string helper=Path.Combine(SystemPasskeySetup.Folder,"WinUp.PasskeyProvider.exe");File.WriteAllText(helper,"previous version fixture");
            Check("platform-provider-refreshes-old-helper",SystemPasskeySetup.EnsureProviderFile()==helper&&SystemPasskeySetup.IsProviderFile(helper));
            DateTime written=File.GetLastWriteTimeUtc(helper);SystemPasskeySetup.EnsureProviderFile();Check("platform-provider-current-file-unchanged",File.GetLastWriteTimeUtc(helper)==written);
            File.Delete(helper);Check("platform-provider-restores-missing-helper",SystemPasskeySetup.EnsureProviderFile()==helper&&SystemPasskeySetup.IsProviderFile(helper));
        }
    }
}
