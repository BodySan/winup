using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;

namespace WinUp {
    static class DesktopDependencies {
        internal static readonly string[] Names={"Microsoft.Web.WebView2.Core.dll","Microsoft.Web.WebView2.WinForms.dll","WebView2Loader.dll"};
        internal static string Folder{get{return Path.Combine(Paths.Data,"runtime","webview2");}}
        static bool configured;
        static readonly object gate=new object();
        internal static Stream Open(string name){return typeof(DesktopDependencies).Assembly.GetManifestResourceStream("desktop-deps/"+name);}
        internal static bool OwnBrowserConnection(){try{if(!BrowserSetup.Enabled||!File.Exists(BrowserSetup.HostManifestPath))return false;var value=new System.Web.Script.Serialization.JavaScriptSerializer().Deserialize<System.Collections.Generic.Dictionary<string,object>>(SafeStorage.ReadTextBounded(BrowserSetup.HostManifestPath,65536));object path;return value!=null&&value.TryGetValue("path",out path)&&path is string&&Proc.SameFile((string)path,System.Windows.Forms.Application.ExecutablePath);}catch{return false;}}
        internal static void Ensure(){
            lock(gate){
            if(configured)return;
            SafePaths.NoReparseParents(Folder);
            Directory.CreateDirectory(Folder);
            foreach(string name in Names){
                string target=Path.Combine(Folder,name);
                using(var source=Open(name)){
                    if(source==null)throw new IOException("В сборке отсутствует компонент интерфейса: "+name);
                    if(File.Exists(target)){
                        SafePaths.NoReparseParents(target);
                        using(var actual=File.OpenRead(target))using(var sha=SHA256.Create()){
                            byte[] expected=sha.ComputeHash(source),found=sha.ComputeHash(actual);
                            if(!expected.SequenceEqual(found))throw new IOException("Компонент нового интерфейса изменён: "+name+". Восстановите его из исходного комплекта этой сборки.");
                        }
                    }else using(var output=new FileStream(target,FileMode.CreateNew,FileAccess.Write,FileShare.None))source.CopyTo(output);
                }
            }
            AppDomain.CurrentDomain.AssemblyResolve+=Resolve;
            var core=Assembly.LoadFrom(Path.Combine(Folder,Names[0]));
            var environment=core.GetType("Microsoft.Web.WebView2.Core.CoreWebView2Environment",true);
            environment.GetMethod("SetLoaderDllFolderPath",BindingFlags.Public|BindingFlags.Static).Invoke(null,new object[]{Folder});
            Assembly.LoadFrom(Path.Combine(Folder,Names[1]));
            configured=true;
            }
        }
        static Assembly Resolve(object sender,ResolveEventArgs args){
            string name=new AssemblyName(args.Name).Name+".dll";
            if(name!=Names[0]&&name!=Names[1])return null;
            return Assembly.LoadFrom(Path.Combine(Folder,name));
        }
        internal static string BundledPath(string root,string name){return Names.Contains(name)?Path.Combine(root,"data","runtime","webview2",name):Path.Combine(root,"data","docs",name);}
    }
}
