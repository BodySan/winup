using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

// The manifest remains signed and intact; ZIP compression metadata/payload is
// deliberately replaced. No signing key or package from the real app is used.
internal static class UpdateCompressionAttackProbe {
    static int Main(string[] args) {
        const string root=@"C:\WinUpAudit\UpdateCompressionProof";
        if(!Assembly.GetExecutingAssembly().Location.StartsWith(@"C:\WinUpAudit\",StringComparison.OrdinalIgnoreCase) || args.Length!=1 || !Path.GetFullPath(args[0]).StartsWith(root+"\\",StringComparison.OrdinalIgnoreCase))return 90;
        Directory.CreateDirectory(root);string path=Path.Combine(root,"modified-deflate.wup");
        var assembly=Assembly.LoadFrom(args[0]);var manifestType=assembly.GetType("WinUp.ComponentManifest");var packageType=assembly.GetType("WinUp.ComponentPackage");
        byte[] normal=Encoding.UTF8.GetBytes("synthetic payload");string sha;
        using(var hash=SHA256.Create())sha=BitConverter.ToString(hash.ComputeHash(normal)).Replace("-","").ToLowerInvariant();
        string json="{\"schema\":1,\"api\":1,\"sequence\":1,\"minApp\":\"1.13.0.0\",\"maxApp\":\"1.13.999.999\",\"versions\":{\"test\":\"1\"},\"files\":{\"one.dll\":{\"size\":"+normal.Length+",\"sha256\":\""+sha+"\"}}}";
        byte[] raw=Encoding.UTF8.GetBytes(json);object baseline=new JavaScriptSerializer().Deserialize(json,manifestType);
        using(var signer=new RSACryptoServiceProvider(3072)) {
            signer.PersistKeyInCsp=false;
            using(var output=File.Create(path))using(var zip=new ZipArchive(output,ZipArchiveMode.Create)) {
                Action<string,byte[]> put=(name,data)=>{using(var file=zip.CreateEntry(name,CompressionLevel.Optimal).Open())file.Write(data,0,data.Length);};
                put("manifest.json",raw);put("manifest.sig",signer.SignData(raw,"SHA256"));put("one.dll",new byte[1024*1024]);
            }
            byte[] bytes=File.ReadAllBytes(path);bool patched=false;
            for(int at=0;at+46<bytes.Length;at++)if(BitConverter.ToUInt32(bytes,at)==0x02014B50) {
                int length=BitConverter.ToUInt16(bytes,at+28);
                if(at+46+length<=bytes.Length && Encoding.UTF8.GetString(bytes,at+46,length)=="one.dll") {
                    Buffer.BlockCopy(BitConverter.GetBytes(normal.Length),0,bytes,at+24,4);
                    int local=(int)BitConverter.ToUInt32(bytes,at+42);Buffer.BlockCopy(BitConverter.GetBytes(normal.Length),0,bytes,local+22,4);patched=true;break;
                }
            }
            if(!patched)return 91;File.WriteAllBytes(path,bytes);
            bool denied=false;string reason="";
            try {using(var package=(IDisposable)Activator.CreateInstance(packageType,BindingFlags.Instance|BindingFlags.NonPublic,null,new object[]{path,signer.ToXmlString(false),baseline,new Version(1,13,0,0)},null)) {}}
            catch(TargetInvocationException error) {
                reason=error.InnerException.Message;
                denied=error.InnerException is InvalidDataException && reason.Contains("превышает подписанный размер");
            }
            Console.WriteLine("signed_manifest_unchanged=True");Console.WriteLine("zip_advertised_uncompressed_bytes="+normal.Length);
            Console.WriteLine("actual_deflate_uncompressed_bytes=1048576");Console.WriteLine("signed_length_limit_triggered="+denied);
            File.WriteAllText(Path.Combine(root,"proof.txt"),"signed_length_limit_triggered="+denied+Environment.NewLine+reason,Encoding.UTF8);
            return denied ? 0 : 1;
        }
    }
}
