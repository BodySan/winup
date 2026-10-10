using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using WinUp.SystemPasskeyNative;

namespace WinUp {
    internal static unsafe class SystemProviderProbe {
        [STAThread]static int Main(string[] args){
            bool ci=args.Contains("--ci")&&Environment.GetEnvironmentVariable("GITHUB_ACTIONS")=="true";
            if((Environment.UserName!="WDAGUtilityAccount"&&!ci)||!Paths.Root.StartsWith(@"C:\WinUpAudit\",StringComparison.OrdinalIgnoreCase))throw new Exception("Synthetic sandbox or disposable CI only");
            AppDomain.CurrentDomain.AssemblyResolve+=(s,e)=>new AssemblyName(e.Name).Name=="KeePassLib"?CoreLoader.Resolve():EmbeddedModules.Resolve(e.Name);
            try{
                if(args.Contains("--encoding-only"))return NativeResponseProbe.Run(Paths.Root);
                if(ci)throw new Exception("CI permits encoding only; provider installation requires Windows Sandbox");
                if(args.Contains("--cache-only")){RunCache();return 0;}
                Run();return 0;
            }catch(Exception ex){Console.WriteLine("FAIL "+ex);return 1;}
        }
        static int cachePassed;
        static void CacheCheck(string name,bool value){if(!value)throw new Exception(name);Console.WriteLine("PASS "+name);cachePassed++;}
        static SystemPasskeyCredential[] Cached(){
            var info=new System.Diagnostics.ProcessStartInfo(Path.Combine(SystemPasskeySetup.Folder,"WinUp.PasskeyProvider.exe"),"--system-passkey-cache-list"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardOutputEncoding=System.Text.Encoding.UTF8,StandardErrorEncoding=System.Text.Encoding.UTF8};
            using(var process=System.Diagnostics.Process.Start(info)){
                var output=process.StandardOutput.ReadToEndAsync();var error=process.StandardError.ReadToEndAsync();
                if(!process.WaitForExit(15000)){process.Kill();throw new Exception("Cache inspection timed out");}
                if(process.ExitCode!=0)throw new Exception(error.Result);
                return new System.Web.Script.Serialization.JavaScriptSerializer().Deserialize<SystemPasskeyCredential[]>(output.Result);
            }
        }
        static void RunCache(){
            System.Windows.Forms.Application.EnableVisualStyles();
            SystemPasskeySetup.TrustCertificate();SystemPasskeySetup.Prepare();
            Console.WriteLine(SystemPasskeySetup.PackageCommand(false));
            try{
            SystemPasskeySetup.UpdateCredentialCache(new[]{new SystemPasskeyCredential{Id=PasskeyPolicy.Encode(Enumerable.Repeat((byte)9,32).ToArray()),Rp="localhost",UserId="AQIDBA",User="synthetic-stale",Display="Synthetic previous process"}});
            var app=new AppStore();app.Settings.WizardDone=true;app.Settings.AutoTypeHotkey=0;app.Settings.BackupDir=Path.Combine(Paths.Root,"backup");app.Save();
            var flags=BindingFlags.Instance|BindingFlags.NonPublic;
            using(var form=new MainForm(app,false)){
                CacheCheck("starting WinUp locked clears metadata left by a previous process",Cached().Length==0);
                var database=KdbxStore.Create("Synthetic-cache-master!",null);
                typeof(MainForm).GetField("vault",flags).SetValue(form,database);
                var first=new LoginEntry{Name="Первый учебный аккаунт",Kind="passkey",Target="localhost",Login="synthetic-first",Args=PasskeyPolicy.Encode(Enumerable.Repeat((byte)7,32).ToArray()),Window="AQIDBA",Password="PRIVATE-SYNTHETIC-NEVER-EXPORT"};
                var second=new LoginEntry{Name="Second synthetic account",Kind="passkey",Target="example.com",Login="synthetic-second",Args=PasskeyPolicy.Encode(Enumerable.Repeat((byte)8,32).ToArray()),Window="BQYHCA",Password="PRIVATE-SYNTHETIC-NEVER-EXPORT"};
                database.Entries.Add(first);database.Entries.Add(second);database.Save();
                typeof(MainForm).GetMethod("ShowOpen",flags).Invoke(form,null);
                var cached=Cached();
                CacheCheck("opening database publishes both passkeys to actual Windows cache",cached.Length==2&&cached.Any(x=>x.Id==first.Args)&&cached.Any(x=>x.Id==second.Args));
                CacheCheck("cache contains Cyrillic labels and user identifiers",cached.Single(x=>x.Id==first.Args).Display==first.Name&&cached.Single(x=>x.Id==first.Args).UserId==first.Window);
                using(var registration=Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\WinUp\SystemPasskeys",true)){
                    registration.SetValue("Root",Paths.Root+"-other-copy");
                    try{form.RefreshSystemPasskeyCache();CacheCheck("a different WinUp folder cannot overwrite the connected provider cache",Cached().Length==2);}
                    finally{registration.SetValue("Root",Paths.Root);}
                }
                CacheCheck("Windows metadata contains no private key or password field",!new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(cached).Contains("PRIVATE-SYNTHETIC-NEVER-EXPORT")&&typeof(SystemPasskeyCredential).GetProperties().All(x=>x.Name!="Password"));
                form.RefreshSystemPasskeyCache();CacheCheck("repeated synchronization does not duplicate passkeys",Cached().Length==2);
                first.Name="Updated account label";first.Login="updated-user";
                CacheCheck("normal save succeeds with cache publication",form.SaveBrowserVault());
                cached=Cached();CacheCheck("saving updates account labels in Windows",cached.Single(x=>x.Id==first.Args).Display==first.Name&&cached.Single(x=>x.Id==first.Args).User==first.Login);
                database.Entries.Remove(second);form.SaveBrowserVault();CacheCheck("deleted key disappears from Windows",Cached().Length==1&&Cached()[0].Id==first.Args);
                database.Entries.Add(new LoginEntry{Name="Duplicate",Kind="passkey",Target=first.Target,Login=first.Login,Args=first.Args,Window=first.Window,Password="SYNTHETIC"});
                database.Entries.Add(new LoginEntry{Name="Site password",Kind="site",Target="https://example.com",Login="password-only",Password="SYNTHETIC"});
                database.Entries.Add(new LoginEntry{Name="Invalid imported key",Kind="passkey",Target="localhost",Args="!invalid",Window="AQIDBA",Password="SYNTHETIC"});
                form.SaveBrowserVault();CacheCheck("duplicates and non-passkey records do not break publication",Cached().Length==1);
                typeof(MainForm).GetMethod("LockVaultCore",flags).Invoke(form,new object[]{true});CacheCheck("locking passwords removes account metadata from Windows",Cached().Length==0);
                int left;StoreResult result;var reopened=KdbxStore.Open("Synthetic-cache-master!",null,out left,out result);
                if(reopened==null||result!=StoreResult.Ok)throw new Exception("Synthetic database did not reopen");
                typeof(MainForm).GetField("vault",flags).SetValue(form,reopened);
                typeof(MainForm).GetMethod("ShowOpen",flags).Invoke(form,null);CacheCheck("unlocking restores available passkeys",Cached().Length==1);
                form.Show();System.Windows.Forms.Application.DoEvents();form.Close();CacheCheck("closing WinUp clears Windows metadata",Cached().Length==0);
            }
            Console.WriteLine("RESULT native-cache passed="+cachePassed+" failed=0");
            }finally{if(SystemPasskeySetup.OwnsRegistration())Console.WriteLine(SystemPasskeySetup.PackageCommand(true));}
        }
        static void Run(){using(var cert=SystemPasskeySetup.Certificate())Console.WriteLine("PASS embedded-msix-signature-matches-public-certificate private="+cert.HasPrivateKey);SystemPasskeySetup.Prepare();Console.WriteLine("PASS native-assets-extracted-from-signed-components");Console.WriteLine(SystemPasskeySetup.PackageCommand(false));Console.WriteLine("STATUS "+SystemPasskeySetup.Status());
            var type=Type.GetTypeFromCLSID(SystemPasskeyProvider.Clsid,true);object native=Activator.CreateInstance(type);try{var provider=(IWinUpPluginAuthenticator)native;int status=-1;int hr=provider.GetLockStatus((IntPtr)(&status));if(hr!=0||status!=0)throw new Exception("Locked COM status mismatch: "+hr+" "+status);Console.WriteLine("PASS actual-windows-com-activation-and-locked-status");}finally{Marshal.FinalReleaseComObject(native);}
            uint version=WebAuthnApi.WebAuthNGetApiVersionNumber();Console.WriteLine("API "+version);WebAuthnAuthenticatorDetailsList* list=null;var options=new WebAuthnAuthenticatorDetailsOptions{dwVersion=1};int result=WebAuthnApi.WebAuthNGetAuthenticatorList(&options,&list);try{Console.WriteLine("LIST 0x"+result.ToString("X8"));if(result==unchecked((int)0x8007001F))Console.WriteLine("BLOCKED actual-platform-create-and-login: Sandbox has no working TPM/device");else if(result<0)Marshal.ThrowExceptionForHR(result);if(list!=null)for(uint i=0;i<list->cAuthenticatorDetails;i++)Console.WriteLine("AUTHENTICATOR "+new string(list->ppAuthenticatorDetails[i]->pwszAuthenticatorName));}finally{if(list!=null)WebAuthnApi.WebAuthNFreeAuthenticatorList(list);}
            Console.WriteLine(SystemPasskeySetup.PackageCommand(true));Console.WriteLine("PASS provider-removed-without-touching-password-database");Console.WriteLine(SystemPasskeySetup.PackageCommand(false));Console.WriteLine("PASS provider-reinstallation");Console.WriteLine("RESULT native-install-com-remove-reinstall=PASS; system-selection-requires-enabled-provider");
        }
    }
}
