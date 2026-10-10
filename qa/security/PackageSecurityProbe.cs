using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;

namespace WinUp {
    internal static class PackageSecurityProbe {
        const string Password="Synthetic-Package-Integrity-2026!";
        static int passed,failed;
        static void Check(string name,bool ok){Console.WriteLine((ok?"PASS ":"FAIL ")+name);if(ok)passed++;else failed++;}
        [STAThread] static int Main(string[] args){
            Console.SetOut(new StreamWriter(Console.OpenStandardOutput(),new UTF8Encoding(false)){AutoFlush=true});
            bool ci=args.Contains("--ci") && Environment.GetEnvironmentVariable("GITHUB_ACTIONS")=="true";
            if(!Paths.Root.StartsWith(@"C:\WinUpAudit\",StringComparison.OrdinalIgnoreCase) || (Environment.UserName!="WDAGUtilityAccount"&&!ci))throw new Exception("Isolated synthetic test only");
            AppDomain.CurrentDomain.AssemblyResolve+=(s,e)=>new AssemblyName(e.Name).Name=="KeePassLib"?CoreLoader.Resolve():EmbeddedModules.Resolve(e.Name);
            string root=Path.Combine(Paths.Root,"package-integrity-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
            try{Run(root);}catch(Exception e){Check("package-integrity-unhandled",false);Console.WriteLine(e);}
            Console.WriteLine("RESULT passed="+passed+" failed="+failed);return failed==0?0:1;
        }
        static void Run(string root){
            string source=Path.Combine(root,"Учебный.bin"),package=Path.Combine(root,"source.tar.age");
            byte[] data=Enumerable.Range(0,180000).Select(x=>(byte)x).ToArray();File.WriteAllBytes(source,data);
            FilePackages.Pack(new[]{source},package,Password,false,CancellationToken.None);
            string normal=Path.Combine(root,"normal");FilePackages.Unpack(package,normal,Password,CancellationToken.None);
            Check("package-integrity-positive-roundtrip",File.ReadAllBytes(Path.Combine(normal,Path.GetFileName(source))).SequenceEqual(data));
            byte[] original=File.ReadAllBytes(package);
            byte[] changed=(byte[])original.Clone();changed[changed.Length/2]^=1;Reject(root,"changed-content",changed,Password);
            Reject(root,"truncated-final-chunk",original.Take(original.Length-1).ToArray(),Password);
            Reject(root,"appended-bytes",original.Concat(new byte[]{0,1,2,3}).ToArray(),Password);
            Reject(root,"wrong-password",original,"Incorrect-synthetic-password!");
            string second=Path.Combine(root,"second.tar.age");FilePackages.Pack(new[]{source},second,Password,false,CancellationToken.None);
            byte[] foreign=File.ReadAllBytes(second);changed=(byte[])original.Clone();Array.Copy(foreign,foreign.Length-100,changed,changed.Length-100,100);
            Reject(root,"foreign-ciphertext-chunk",changed,Password);
            string existing=Path.Combine(root,"existing");Directory.CreateDirectory(existing);File.WriteAllText(Path.Combine(existing,"keep.txt"),"Synthetic-original");
            bool rejected=false;try{FilePackages.Unpack(package,existing,Password,CancellationToken.None);}catch(IOException){rejected=true;}
            Check("package-integrity-existing-output-preserved",rejected && File.ReadAllText(Path.Combine(existing,"keep.txt"))=="Synthetic-original" && Directory.GetFiles(existing).Length==1);
        }
        static void Reject(string root,string name,byte[] bytes,string password){
            string input=Path.Combine(root,name+".tar.age"),output=Path.Combine(root,name+"-output");File.WriteAllBytes(input,bytes);
            bool rejected=false;try{FilePackages.Unpack(input,output,password,CancellationToken.None);}catch(IOException){rejected=true;}
            Check("package-integrity-"+name,rejected && !Directory.Exists(output) && Directory.GetDirectories(root,".winup-unpack-*").Length==0);
        }
    }
}
