using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace WinUp {
    internal sealed class AuthorizedInstallation {
        public int schema{get;set;}
        public AppItem[] items{get;set;}
        public bool silent{get;set;}
    }
    internal static class InstallAuthorization {
        const int Maximum=128*1024;
        static JavaScriptSerializer Json(){return new JavaScriptSerializer{MaxJsonLength=Maximum,RecursionLimit=16};}
        internal static void Validate(AuthorizedInstallation value){
            if(value==null||value.schema!=1||value.items==null||value.items.Length==0||value.items.Length>200)
                throw new IOException("Разрешение на установку отсутствует или повреждено.");
            foreach(var item in value.items){
                if(item==null||string.IsNullOrWhiteSpace(item.Id)||string.IsNullOrWhiteSpace(item.Name)||item.Name.Length>1024||
                    string.IsNullOrWhiteSpace(item.File)||!Path.IsPathRooted(item.File)||item.File.Length>32700||item.File.Any(char.IsControl)||
                    (item.Args??"").Length>32700||!string.Equals(Path.GetFullPath(item.File),item.File,StringComparison.OrdinalIgnoreCase))
                    throw new IOException("В разрешении на установку есть неверная запись.");
            }
        }
        internal static bool SameProcess(int pid,long started,string executable){
            return Proc.WithProcess(pid,(handle,identity)=>identity.Started==started&&Proc.SameFile(identity.Path,executable));
        }
        internal sealed class Session:IDisposable {
            readonly NamedPipeServerStream pipe;readonly byte[] payload;
            readonly ManualResetEventSlim launched=new ManualResetEventSlim();
            internal readonly string Name="WinUp-install-"+Guid.NewGuid().ToString("N");
            internal readonly int Owner=Process.GetCurrentProcess().Id;
            internal readonly long Started=Process.GetCurrentProcess().StartTime.ToUniversalTime().ToFileTimeUtc();
            int child,disposed;long childStarted;
            internal Session(AuthorizedInstallation value){
                Validate(value);payload=Encoding.UTF8.GetBytes(Json().Serialize(value));if(payload.Length>Maximum)throw new IOException("Список установки слишком большой.");
                var security=new PipeSecurity();security.SetAccessRuleProtection(true,false);
                security.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User,PipeAccessRights.FullControl,AccessControlType.Allow));
                pipe=new NamedPipeServerStream(Name,PipeDirection.Out,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous,4096,4096,security);
            }
            internal void Bind(Process process){child=process.Id;childStarted=process.StartTime.ToUniversalTime().ToFileTimeUtc();launched.Set();}
            internal Task Serve(){return Task.Run(()=>{
                var waiting=pipe.BeginWaitForConnection(null,null);
                using(waiting.AsyncWaitHandle){if(!waiting.AsyncWaitHandle.WaitOne(120000))throw new IOException("Время ожидания установки истекло.");pipe.EndWaitForConnection(waiting);}
                if(!launched.Wait(5000)||Proc.ClientPid(pipe)!=child||!SameProcess(child,childStarted,Application.ExecutablePath))
                    throw new IOException("Установку запросил другой процесс. Операция отменена.");
                byte[] length=BitConverter.GetBytes(payload.Length);
                Write(pipe,length);Write(pipe,payload);
            });}
            public void Dispose(){if(Interlocked.Exchange(ref disposed,1)==0){pipe.Dispose();launched.Dispose();Array.Clear(payload,0,payload.Length);}}
        }
        static void Write(Stream stream,byte[] data){var pending=stream.BeginWrite(data,0,data.Length,null,null);using(pending.AsyncWaitHandle){if(!pending.AsyncWaitHandle.WaitOne(5000))throw new IOException("Установка не прочитала разрешение.");stream.EndWrite(pending);}}
        static void Read(Stream stream,byte[] data){int offset=0;while(offset<data.Length){var pending=stream.BeginRead(data,offset,data.Length-offset,null,null);int read;using(pending.AsyncWaitHandle){if(!pending.AsyncWaitHandle.WaitOne(5000))throw new IOException("Разрешение на установку не получено.");read=stream.EndRead(pending);}if(read==0)throw new EndOfStreamException();offset+=read;}}
        internal static AuthorizedInstallation Receive(string name,int owner,long started){
            if(name==null||!System.Text.RegularExpressions.Regex.IsMatch(name,@"\AWinUp-install-[a-f0-9]{32}\z")||owner<=0||started<=0)
                throw new IOException("Установка запускается кнопкой «Установить отмеченные» в основном окне WinUp.");
            using(var pipe=new NamedPipeClientStream(".",name,PipeDirection.In,PipeOptions.Asynchronous)){
                pipe.Connect(5000);
                if(Proc.ServerPid(pipe)!=owner||!SameProcess(owner,started,Application.ExecutablePath))throw new IOException("Основное окно установки не прошло проверку.");
                var length=new byte[4];Read(pipe,length);int count=BitConverter.ToInt32(length,0);
                if(count<1||count>Maximum)throw new IOException("Неверный размер разрешения на установку.");
                var data=new byte[count];Read(pipe,data);var value=Json().Deserialize<AuthorizedInstallation>(new UTF8Encoding(false,true).GetString(data));Validate(value);return value;
            }
        }
        internal static AuthorizedInstallation Receive(string[] args){
            Func<string,string> option=key=>{int at=Array.IndexOf(args,key);return at>=0&&at+1<args.Length?args[at+1]:null;};
            int owner;long started;if(!int.TryParse(option("--install-owner"),out owner)||!long.TryParse(option("--install-started"),out started))throw new IOException("Установка запускается из основного окна WinUp.");
            return Receive(option("--install-pipe"),owner,started);
        }
        internal static async Task Launch(AppItem[] items,bool silent){
            // Snapshot precisely what the window approved. The elevated process
            // does not re-read mutable apps.json or trust a hash supplied by argv.
            var value=new AuthorizedInstallation{schema=1,silent=silent,items=items.Select(a=>new AppItem{Id=a.Id,Name=a.Name,File=Paths.Full(a.File),Args=(a.Args??"").Replace("{root}",Paths.Root),Kind=a.Kind}).ToArray()};
            using(var session=new Session(value)){
                Task delivery=session.Serve();
                try{
                    string args="--install authorized --install-pipe "+session.Name+" --install-owner "+session.Owner+" --install-started "+session.Started;
                    using(var child=Process.Start(new ProcessStartInfo(Application.ExecutablePath,args){UseShellExecute=true,Verb="runas"})){
                        if(child==null)throw new IOException("Windows не запустила установку.");session.Bind(child);await delivery.ConfigureAwait(false);
                    }
                }catch{session.Dispose();var observation=delivery.ContinueWith(task=>{var ignored=task.Exception;},TaskContinuationOptions.OnlyOnFaulted);throw;}
            }
        }
    }
}
