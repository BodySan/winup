using System;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace WinUp {
    internal static class ProviderProgram {
        [STAThread]static void Main(string[] args){try{if(args.Contains("--system-passkey-register-quiet"))Environment.ExitCode=SystemPasskeyProvider.Register();else if(args.Contains("--system-passkey-remove-quiet"))Environment.ExitCode=SystemPasskeyProvider.Remove();else if(args.Contains("--system-passkey"))SystemPasskeyProvider.Run();else Environment.ExitCode=2;}catch(Exception ex){Environment.ExitCode=Marshal.GetHRForException(ex);}}
    }
    internal static class Paths {internal static readonly string Root=Path.GetDirectoryName(AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\'));}
    internal static class BrowserPipe {internal static string Name{get{using(var sha=SHA256.Create())return "WinUp-browser-"+Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(Paths.Root.ToUpperInvariant()))).Replace("/","_").Replace("+","-").TrimEnd('=');}}}
    internal static class Proc {
        [DllImport("kernel32.dll")]static extern bool GetNamedPipeServerProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe,out uint pid);
        [DllImport("kernel32.dll")]static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern bool QueryFullProcessImageName(IntPtr process,uint flags,StringBuilder path,ref int count);
        [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr handle);
        internal static int ServerPid(PipeStream pipe){uint pid;return GetNamedPipeServerProcessId(pipe.SafePipeHandle,out pid)?(int)pid:0;}
        internal static string ImagePath(int pid){IntPtr handle=OpenProcess(0x1000,false,pid);if(handle==IntPtr.Zero)return null;try{int size=32768;var result=new StringBuilder(size);return QueryFullProcessImageName(handle,0,result,ref size)?result.ToString():null;}finally{CloseHandle(handle);}}
        internal static bool SameFile(string path,string expected){return path!=null&&string.Equals(Path.GetFullPath(path),Path.GetFullPath(expected),StringComparison.OrdinalIgnoreCase);}
    }
    internal static class PasskeyPolicy {
        internal static string Encode(byte[] value){return Convert.ToBase64String(value).TrimEnd('=').Replace('+','-').Replace('/','_');}
        internal static byte[] Decode(string text,int min,int max){if(text==null||text.Length>(max*4/3+8)||text.Any(c=>!(c>='A'&&c<='Z'||c>='a'&&c<='z'||c>='0'&&c<='9'||c=='_'||c=='-')))throw new IOException("Invalid identifier");string value=text.Replace('-','+').Replace('_','/');var data=Convert.FromBase64String(value+new string('=',(4-value.Length%4)%4));if(data.Length<min||data.Length>max)throw new IOException("Invalid identifier length");return data;}
    }
    internal static class ProviderPublicData {
        internal static byte[] SystemAuthenticatorInfo(){using(var input=typeof(ProviderPublicData).Assembly.GetManifestResourceStream("authenticator-info.cbor"))using(var output=new MemoryStream()){if(input==null)throw new IOException("Authenticator metadata unavailable");input.CopyTo(output);return output.ToArray();}}
        static void Header(Stream stream,int major,int size){if(size<24)stream.WriteByte((byte)(major*32+size));else if(size<=255){stream.WriteByte((byte)(major*32+24));stream.WriteByte((byte)size);}else if(size<=65535){stream.WriteByte((byte)(major*32+25));stream.WriteByte((byte)(size>>8));stream.WriteByte((byte)size);}else throw new IOException("Authenticator response too large");}
        static void Text(Stream stream,string text){byte[] bytes=Encoding.UTF8.GetBytes(text);Header(stream,3,bytes.Length);stream.Write(bytes,0,bytes.Length);}
        internal static byte[] Attestation(byte[] data){using(var output=new MemoryStream()){Header(output,5,3);Text(output,"fmt");Text(output,"none");Text(output,"attStmt");Header(output,5,0);Text(output,"authData");Header(output,2,data.Length);output.Write(data,0,data.Length);return output.ToArray();}}
    }
}
