using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace WinUp {
    internal static class EmbeddedModules {
        static readonly string[] names = { "WinUp.PasskeyEngine", "BouncyCastle.Cryptography", "CBOR", "Numbers" };
        static readonly Dictionary<string,Assembly> loaded = new Dictionary<string,Assembly>();
        public static Assembly Resolve(string fullName) {
            string name = new AssemblyName(fullName).Name;
            if (Array.IndexOf(names,name)<0) return null;
            lock(loaded) {
                Assembly value;
                if(loaded.TryGetValue(name,out value)) return value;
                using(var input=ComponentResources.Open(name+".dll")) {
                    if(input==null) return null;
                    using(var bytes=new MemoryStream()) { input.CopyTo(bytes); value=Assembly.Load(bytes.ToArray()); }
                }
                loaded[name]=value; return value;
            }
        }
        public static void RejectAdjacent() {
            foreach(string name in names) if(File.Exists(Path.Combine(Paths.Root,name+".dll")))
                throw new IOException("Уберите постороннюю библиотеку "+name+".dll из папки WinUp: программа использует встроенную копию.");
        }
    }
}
