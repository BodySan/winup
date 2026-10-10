using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace WinUp {
    internal static class NativeResponseProbe {
        internal static int Run(string root) {
            string pem = null;
            try {
                byte[] cose, spki;
                WinUp.PasskeyEngine.Keys.Generate(-7, out pem, out cose, out spki);
                byte[] id = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
                byte[] hash = Enumerable.Range(32, 32).Select(i => (byte)i).ToArray();
                byte[] user = new byte[] { 1, 2, 3, 4 };
                byte[] create = WinUp.PasskeyEngine.Keys.RegisterData("localhost", id, cose);
                byte[] get = WinUp.PasskeyEngine.Keys.AssertionData("localhost", true, false);
                byte[] signature = WinUp.PasskeyEngine.Keys.Sign(pem, get.Concat(hash).ToArray());
                uint length;
                IntPtr encoded;
                int hr = WinUpPluginAuthenticator.EncodeRegistration(create, id, out length, out encoded);
                File.WriteAllText(Path.Combine(root, "encoding-proof.txt"), "CREATE HRESULT=0x" + hr.ToString("X8") + " bytes=" + length + "\n");
                if (hr < 0) Marshal.ThrowExceptionForHR(hr);
                var data = new byte[length];
                Marshal.Copy(encoded, data, 0, data.Length);
                File.WriteAllBytes(Path.Combine(root, "encoded-create.cbor"), data);
                hr = WinUpPluginAuthenticator.EncodeAssertion(get, id, signature, user, out length, out encoded);
                File.AppendAllText(Path.Combine(root, "encoding-proof.txt"), "GET HRESULT=0x" + hr.ToString("X8") + " bytes=" + length + "\n");
                if (hr < 0) Marshal.ThrowExceptionForHR(hr);
                data = new byte[length];
                Marshal.Copy(encoded, data, 0, data.Length);
                File.WriteAllBytes(Path.Combine(root, "encoded-get.cbor"), data);
                File.WriteAllText(Path.Combine(root, "encoding-public.json"), new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(new {
                    id = PasskeyPolicy.Encode(id), hash = PasskeyPolicy.Encode(hash),
                    publicKey = PasskeyPolicy.Encode(spki), createAuth = PasskeyPolicy.Encode(create),
                    getAuth = PasskeyPolicy.Encode(get), userId = PasskeyPolicy.Encode(user)
                }));
                Console.WriteLine("PASS Windows encoded synthetic registration and assertion responses");
                return 0;
            } catch (EntryPointNotFoundException) {
                Console.WriteLine("SKIP native response encoding: this Windows version has no provider encoding API");
                return 3;
            } catch (Exception ex) {
                File.AppendAllText(Path.Combine(root, "encoding-proof.txt"), ex.ToString());
                Console.WriteLine("FAIL " + ex);
                return 1;
            } finally { Secure.Wipe(pem); }
        }
    }
}
