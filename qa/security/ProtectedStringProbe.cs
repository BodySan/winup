using System;
using System.Reflection;
using KeePassLib.Security;
class ProtectedStringProbe
{
    static void Main()
    {
        AppDomain.CurrentDomain.AssemblyResolve += (s,e) => Assembly.LoadFile(@"C:\WinUp\work\src\lib\KeePassLib.dll");
        Probe();
    }
    static unsafe void Probe()
    {
        string input = new string("synthetic-marker-for-probe".ToCharArray());
        var ps = new ProtectedString(true,input);
        Console.WriteLine("ReadString same input=" + ReferenceEquals(input,ps.ReadString()));
        foreach (var f in typeof(ProtectedString).GetFields(BindingFlags.NonPublic|BindingFlags.Instance))
            Console.WriteLine(f.Name + " type=" + f.FieldType.Name + " same input=" + ReferenceEquals(input,f.GetValue(ps)));
        fixed(char* p = input) for(int i=0;i<input.Length;i++) p[i]='\0';
        Console.WriteLine("Value correct after wiping input=" + (ps.ReadString()=="synthetic-marker-for-probe"));
        var read = ps.ReadString();
        fixed(char* p = read) for(int i=0;i<read.Length;i++) p[i]='\0';
        Console.WriteLine("Value correct after wiping read=" + (ps.ReadString()=="synthetic-marker-for-probe"));
        var bytes = System.Text.Encoding.UTF8.GetBytes("synthetic-marker-for-probe");
        var pb = new ProtectedString(true,bytes);
        Array.Clear(bytes,0,bytes.Length);
        Console.WriteLine("Byte constructor after input clear=" + (pb.ReadString()=="synthetic-marker-for-probe"));
        foreach (var f in typeof(ProtectedString).GetFields(BindingFlags.NonPublic|BindingFlags.Instance))
            Console.WriteLine("byte field " + f.Name + " null=" + (f.GetValue(pb)==null));
        var readBytes = pb.ReadUtf8();
        Array.Clear(readBytes,0,readBytes.Length);
        var text = pb.ReadString();
        fixed(char* p=text) for(int i=0;i<text.Length;i++) p[i]='\0';
        Console.WriteLine("Byte constructor after read buffers clear=" + (pb.ReadString()=="synthetic-marker-for-probe"));
    }
}
