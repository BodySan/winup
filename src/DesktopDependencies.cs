using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace WinUp {
    static class DesktopDependencies {
        internal static readonly string[] Names={"Microsoft.Web.WebView2.Core.dll","Microsoft.Web.WebView2.WinForms.dll","WebView2Loader.dll"};
        internal static Stream Open(string name){return typeof(DesktopDependencies).Assembly.GetManifestResourceStream("desktop-deps/"+name);}
        internal static bool OwnBrowserConnection(){try{if(!BrowserSetup.Enabled||!File.Exists(BrowserSetup.HostManifestPath))return false;var value=new System.Web.Script.Serialization.JavaScriptSerializer().Deserialize<System.Collections.Generic.Dictionary<string,object>>(SafeStorage.ReadTextBounded(BrowserSetup.HostManifestPath,65536));object path;return value!=null&&value.TryGetValue("path",out path)&&path is string&&Proc.SameFile((string)path,System.Windows.Forms.Application.ExecutablePath);}catch{return false;}}
        internal static void Ensure(){
            SafePaths.NoReparseParents(Paths.Root);
            foreach(string name in Names){
                string target=Path.Combine(Paths.Root,name);
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
        }
    }
}
