using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace WinUp
{
    sealed class LocalApplication
    {
        public string Name, Target, Source;
        public override string ToString() { return Name; }
    }

    // Windows supplies stable app identifiers, including Store apps whose executable
    // path changes with each update. Discovery reads local metadata and never launches it.
    static class LocalApplications
    {
        internal const string ShellPrefix = "shell:AppsFolder\\";
        static readonly object gate = new object();
        static Task<List<LocalApplication>> pending;
        static DateTime lastScan;
        public static bool IsShell(string value) { return (value ?? "").StartsWith(ShellPrefix, StringComparison.OrdinalIgnoreCase); }
        static bool SafeId(string id) { return !string.IsNullOrWhiteSpace(id) && id.Length <= 512 && id.IndexOfAny(new[] {'\r','\n','\0','"','<','>','|','?','*'}) < 0 && !id.Contains("://"); }
        static object Call(object value, string name, BindingFlags flags, params object[] args) {
            return value.GetType().InvokeMember(name, flags, null, value, args);
        }
        static void Release(object value) { if(value != null && Marshal.IsComObject(value)) Marshal.FinalReleaseComObject(value); }
        public static Task<List<LocalApplication>> Scan(bool refresh = false) {
            lock(gate) {
                if(pending != null && ((!pending.IsCompleted && DateTime.UtcNow-lastScan < TimeSpan.FromSeconds(15)) || (!refresh && pending.IsCompleted && DateTime.UtcNow-lastScan < TimeSpan.FromSeconds(20)))) return pending;
                var completion = new TaskCompletionSource<List<LocalApplication>>(); pending=completion.Task;lastScan=DateTime.UtcNow;
                var thread=new Thread(delegate() { try { completion.SetResult(Read()); } catch { completion.SetResult(new List<LocalApplication>()); } });
                thread.IsBackground=true;thread.SetApartmentState(ApartmentState.STA);thread.Start();return pending;
            }
        }
        public static async Task<List<LocalApplication>> Available(bool refresh = false) {
            var scan=Scan(refresh);return await Task.WhenAny(scan,Task.Delay(6000))==scan ? await scan : new List<LocalApplication>();
        }
        static List<LocalApplication> Read() {
            var result=new List<LocalApplication>();object shell=null,folder=null,items=null;
            try {
                shell=Activator.CreateInstance(Type.GetTypeFromProgID("Shell.Application"));
                folder=Call(shell,"NameSpace",BindingFlags.InvokeMethod,"shell:AppsFolder");
                if(folder != null) {
                    items=Call(folder,"Items",BindingFlags.InvokeMethod);
                    int count=Math.Min(5000,Convert.ToInt32(Call(items,"Count",BindingFlags.GetProperty)));
                    for(int i=0;i<count;i++) {
                        object item=null;
                        try {
                            item=Call(items,"Item",BindingFlags.InvokeMethod,i);
                            string name=Convert.ToString(Call(item,"Name",BindingFlags.GetProperty));
                            string id=Convert.ToString(Call(item,"ExtendedProperty",BindingFlags.InvokeMethod,"System.AppUserModel.ID"));
                            if(!SafeId(id) || string.IsNullOrWhiteSpace(name) || Regex.IsMatch(name,"uninstall|деинсталл|удалить|maintenance",RegexOptions.IgnoreCase))continue;
                            if(id.IndexOf('!')<0 && Regex.IsMatch(id,@"\.(html?|chm|pdf|txt|url)$",RegexOptions.IgnoreCase))continue;
                            result.Add(new LocalApplication {Name=name,Target=ShellPrefix+id,Source=id.IndexOf('!')>=0 ? "Microsoft Store / пакет Windows" : "Список приложений Windows"});
                        } catch {} finally {Release(item);}
                    }
                }
            } catch {} finally {Release(items);Release(folder);Release(shell);}
            foreach(var root in new[] {Environment.GetFolderPath(Environment.SpecialFolder.Programs),Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms)}) {
                if(!Directory.Exists(root))continue;
                var directories=new Queue<string>();directories.Enqueue(root);int visited=0;
                while(directories.Count>0 && visited++<1000) {
                    var dir=directories.Dequeue();
                    try {
                        foreach(var child in Directory.GetDirectories(dir))if((File.GetAttributes(child)&FileAttributes.ReparsePoint)==0)directories.Enqueue(child);
                        foreach(var file in Directory.GetFiles(dir,"*.lnk")) {
                            var name=Path.GetFileNameWithoutExtension(file);
                            if(Regex.IsMatch(name,"uninstall|деинсталл|удалить|maintenance",RegexOptions.IgnoreCase))continue;
                            if(!result.Any(a=>Normalize(a.Name)==Normalize(name)))result.Add(new LocalApplication {Name=name,Target=Paths.Rel(file),Source="Ярлык меню «Пуск»"});
                        }
                    } catch {}
                }
            }
            return result.GroupBy(a=>a.Target,StringComparer.OrdinalIgnoreCase).Select(g=>g.First()).OrderBy(a=>a.Name,StringComparer.CurrentCultureIgnoreCase).ToList();
        }
        internal static string Normalize(string name) { return Regex.Replace((name ?? "").ToLowerInvariant(),@"[^\p{L}\p{N}]",""); }
        internal static string ServiceName(string name, string site) {
            string n=Normalize(AppStore.TemplateName(name));
            switch(n) {case "steamcommunity":return "steam";}
            string host=SiteDomain.HostOf(site);
            if(host=="chatgpt.com" || host=="chat.openai.com")return "chatgpt";
            if(host=="icloud.com" || host=="www.icloud.com")return "icloud";
            return n;
        }
        public static LocalApplication Match(IEnumerable<LocalApplication> apps,string name,string site) {
            string wanted=ServiceName(name,site);
            var matches=apps.Where(a=>Normalize(a.Name)==wanted).ToList();
            // Ambiguous installed editions need an explicit choice, never a fuzzy first hit.
            return matches.Count==1 ? matches[0] : null;
        }
        public static bool Exists(string value,IEnumerable<LocalApplication> apps) {
            if(IsShell(value))return SafeId(value.Substring(ShellPrefix.Length)) && apps.Any(a=>string.Equals(a.Target,value,StringComparison.OrdinalIgnoreCase));
            try { string path=Paths.Full(value),ext=Path.GetExtension(path);return File.Exists(path) && (ext.Equals(".exe",StringComparison.OrdinalIgnoreCase) || ext.Equals(".lnk",StringComparison.OrdinalIgnoreCase)); }catch{return false;}
        }
        public static ProcessStartInfo LaunchInfo(string value,string args,IEnumerable<LocalApplication> apps) {
            if(!Exists(value,apps))throw new InvalidOperationException("Приложение не найдено на этом ПК. Выберите установленное приложение или установите его и повторите поиск.");
            if(IsShell(value)) {
                if(!string.IsNullOrWhiteSpace(args))throw new InvalidOperationException("Для запуска через список приложений Windows параметры не поддерживаются. Очистите параметры или выберите файл .exe.");
                return new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"explorer.exe"),"\""+value+"\"") {UseShellExecute=true};
            }
            var path=Paths.Full(value);return new ProcessStartInfo(path,args ?? "") {UseShellExecute=true,WorkingDirectory=Path.GetDirectoryName(path)};
        }
    }
}
