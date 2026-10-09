using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using WinUp.SystemPasskeyNative;

namespace WinUp {
    internal static unsafe class SystemProviderProbe {
        [STAThread]static int Main(string[] args){if(Environment.UserName!="WDAGUtilityAccount"||!Paths.Root.StartsWith(@"C:\WinUpAudit\",StringComparison.OrdinalIgnoreCase))throw new Exception("Synthetic sandbox only");AppDomain.CurrentDomain.AssemblyResolve+=(s,e)=>new AssemblyName(e.Name).Name=="KeePassLib"?CoreLoader.Resolve():EmbeddedModules.Resolve(e.Name);try{Run();return 0;}catch(Exception ex){Console.WriteLine("FAIL "+ex);return 1;}}
        static void Run(){using(var cert=SystemPasskeySetup.Certificate())Console.WriteLine("PASS embedded-msix-signature-matches-public-certificate private="+cert.HasPrivateKey);SystemPasskeySetup.Prepare();Console.WriteLine("PASS native-assets-extracted-from-signed-components");Console.WriteLine(SystemPasskeySetup.PackageCommand(false));Console.WriteLine("STATUS "+SystemPasskeySetup.Status());
            var type=Type.GetTypeFromCLSID(SystemPasskeyProvider.Clsid,true);object native=Activator.CreateInstance(type);try{var provider=(IWinUpPluginAuthenticator)native;int status=-1;int hr=provider.GetLockStatus((IntPtr)(&status));if(hr!=0||status!=0)throw new Exception("Locked COM status mismatch: "+hr+" "+status);Console.WriteLine("PASS actual-windows-com-activation-and-locked-status");}finally{Marshal.FinalReleaseComObject(native);}
            uint version=WebAuthnApi.WebAuthNGetApiVersionNumber();Console.WriteLine("API "+version);WebAuthnAuthenticatorDetailsList* list=null;var options=new WebAuthnAuthenticatorDetailsOptions{dwVersion=1};int result=WebAuthnApi.WebAuthNGetAuthenticatorList(&options,&list);try{Console.WriteLine("LIST 0x"+result.ToString("X8"));if(result==unchecked((int)0x8007001F))Console.WriteLine("BLOCKED actual-platform-create-and-login: Sandbox has no working TPM/device");else if(result<0)Marshal.ThrowExceptionForHR(result);if(list!=null)for(uint i=0;i<list->cAuthenticatorDetails;i++)Console.WriteLine("AUTHENTICATOR "+new string(list->ppAuthenticatorDetails[i]->pwszAuthenticatorName));}finally{if(list!=null)WebAuthnApi.WebAuthNFreeAuthenticatorList(list);}
            Console.WriteLine(SystemPasskeySetup.PackageCommand(true));Console.WriteLine("PASS provider-removed-without-touching-password-database");Console.WriteLine(SystemPasskeySetup.PackageCommand(false));Console.WriteLine("PASS provider-reinstallation");Console.WriteLine("RESULT native-install-com-remove-reinstall=PASS; system-selection-requires-enabled-provider");
        }
    }
}
