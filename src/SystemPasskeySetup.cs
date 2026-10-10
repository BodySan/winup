using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using WinUp.SystemPasskeyNative;

namespace WinUp {
    internal sealed class SystemProviderPackage {public int schema{get;set;}public string thumbprint{get;set;}public string packageHash{get;set;}}
    internal static class SystemPasskeySetup {
        internal static readonly string[] Files={"WinUp.Passkeys.msix","WinUp.Passkeys.cer","package.json","Logo.png","setup.ps1","WinUp.PasskeyProvider.exe"};
        internal static bool IsProviderFile(string path){string expected=Path.Combine(Folder,"WinUp.PasskeyProvider.exe");if(!Proc.SameFile(path,expected))return false;using(var actual=File.OpenRead(expected))using(var bundled=ComponentResources.Open("system-passkeys/WinUp.PasskeyProvider.exe"))return ComponentPackage.Hash(actual)==ComponentPackage.Hash(bundled);}
        internal static string Folder{get{return Path.Combine(Paths.Root,"system-passkeys");}}
        internal static bool OwnsRegistration(){
            try{using(var key=Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\WinUp\SystemPasskeys")){
                string root=key==null?null:key.GetValue("Root") as string;
                return root!=null&&string.Equals(Path.GetFullPath(root).TrimEnd('\\'),Paths.Root.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase);
            }}catch{return false;}
        }
        internal static void UpdateCredentialCache(System.Collections.Generic.IEnumerable<SystemPasskeyCredential> credentials){
            if(!OwnsRegistration())return;
            string helper=Path.Combine(Folder,"WinUp.PasskeyProvider.exe");if(!IsProviderFile(helper))throw new IOException("Подключение Windows использует другой выпуск WinUp. Нажмите «Подключить к Windows…» ещё раз.");
            byte[] payload=Encoding.UTF8.GetBytes(new JavaScriptSerializer{MaxJsonLength=4*1024*1024}.Serialize(credentials));
            if(payload.Length>4*1024*1024)throw new IOException("Список ключей слишком большой.");
            var info=new ProcessStartInfo(helper,"--system-passkey-sync"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardOutputEncoding=Encoding.UTF8,StandardErrorEncoding=Encoding.UTF8};
            using(var process=Process.Start(info)){
                var output=process.StandardOutput.ReadToEndAsync();var error=process.StandardError.ReadToEndAsync();
                process.StandardInput.BaseStream.Write(payload,0,payload.Length);process.StandardInput.Close();
                if(!process.WaitForExit(15000)){process.Kill();throw new IOException("Windows не завершила обновление списка ключей.");}
                if(process.ExitCode!=0)throw new IOException((error.Result+" "+output.Result).Trim());
            }
        }
        static byte[] Resource(string name){using(var input=ComponentResources.Open("system-passkeys/"+name)){if(input==null||input.Length>16*1024*1024)throw new IOException("Пакет подключения к Windows не найден.");using(var output=new MemoryStream()){input.CopyTo(output);return output.ToArray();}}}
        internal static X509Certificate2 Certificate(){var metadata=new JavaScriptSerializer().Deserialize<SystemProviderPackage>(Encoding.UTF8.GetString(Resource("package.json")));var cert=new X509Certificate2(Resource("WinUp.Passkeys.cer"));if(metadata==null||metadata.schema!=1||cert.Subject!="CN=WinUp"||!cert.Thumbprint.Equals(metadata.thumbprint,StringComparison.OrdinalIgnoreCase)||cert.HasPrivateKey||cert.NotAfter<DateTime.Now||cert.NotBefore>DateTime.Now)throw new IOException("Сертификат выпуска WinUp не прошёл проверку.");byte[] package=Resource("WinUp.Passkeys.msix");using(var input=new MemoryStream(package)){if(ComponentPackage.Hash(input)!=metadata.packageHash)throw new IOException("Пакет подключения к Windows изменён.");input.Position=0;using(var zip=new ZipArchive(input,ZipArchiveMode.Read,true)){var signature=zip.GetEntry("AppxSignature.p7x");if(signature==null||signature.Length>1024*1024)throw new IOException("В пакете нет подписи издателя.");using(var source=signature.Open())using(var memory=new MemoryStream()){source.CopyTo(memory);var value=memory.ToArray();if(value.Length<5||Encoding.ASCII.GetString(value,0,4)!="PKCX")throw new IOException("Неправильный формат подписи пакета.");var cms=new SignedCms();cms.Decode(value.Skip(4).ToArray());cms.CheckSignature(true);if(cms.SignerInfos.Count!=1||cms.SignerInfos[0].Certificate==null||cms.SignerInfos[0].Certificate.Thumbprint!=cert.Thumbprint)throw new IOException("Подпись пакета принадлежит другому издателю.");}}}return cert;}
        internal static void TrustCertificate(){using(var cert=Certificate())using(var store=new X509Store(StoreName.TrustedPeople,StoreLocation.LocalMachine)){store.Open(OpenFlags.ReadWrite);store.Add(cert);}}
        internal static bool IsTrusted(){using(var cert=Certificate())using(var store=new X509Store(StoreName.TrustedPeople,StoreLocation.LocalMachine)){store.Open(OpenFlags.ReadOnly);return store.Certificates.Find(X509FindType.FindByThumbprint,cert.Thumbprint,false).Count>0;}}
        internal static void Prepare(){using(var cert=Certificate()){}SafePaths.NoReparseParents(Folder);Directory.CreateDirectory(Folder);foreach(var name in Files){var data=Resource(name);try{string target=Path.Combine(Folder,name);SafePaths.NoReparseParents(target);bool same=false;if(File.Exists(target))using(var existing=File.OpenRead(target))using(var bundled=new MemoryStream(data))same=ComponentPackage.Hash(existing)==ComponentPackage.Hash(bundled);if(!same)Paths.AtomicWrite(target,data);}finally{Array.Clear(data,0,data.Length);}}}
        internal static void EnsureTrusted(){if(IsTrusted())return;using(var process=Process.Start(new ProcessStartInfo(Application.ExecutablePath,"--system-passkey-trust"){UseShellExecute=true,Verb="runas"})){process.WaitForExit();if(process.ExitCode!=0||!IsTrusted())throw new IOException("Windows не разрешила доверие к сертификату WinUp. Подключение отменено.");}}
        internal static string PackageCommand(bool remove){Prepare();var info=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),@"WindowsPowerShell\v1.0\powershell.exe"),"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "+Quote(Path.Combine(Folder,"setup.ps1"))+" -Root "+Quote(Paths.Root)+" -Mode "+(remove?"remove":"install")){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardOutputEncoding=Encoding.UTF8,StandardErrorEncoding=Encoding.UTF8};using(var p=Process.Start(info)){var output=p.StandardOutput.ReadToEndAsync();var error=p.StandardError.ReadToEndAsync();if(!p.WaitForExit(120000)){p.Kill();throw new IOException("Windows не завершила подключение провайдера. Повторите проверку состояния.");}if(p.ExitCode!=0)throw new IOException((error.Result+"\n"+output.Result).Trim());return output.Result.Trim();}}
        static string Quote(string text){if(text.IndexOf('"')>=0||text.Any(char.IsControl))throw new IOException("Недопустимый путь.");return "\""+text.TrimEnd('\\')+"\"";}
        internal static unsafe string Status(){try{SystemPasskeyNative.AuthenticatorState state;int hr=WebAuthnPluginApi.WebAuthNPluginGetAuthenticatorState(ref SystemPasskeyProvider.Clsid,&state);if(hr<0)return "WinUp ещё не подключён к Windows.";return state==AuthenticatorState.AuthenticatorState_Enabled?"WinUp включён в окне ключей доступа Windows.":"WinUp подключён. Включите его в дополнительных параметрах ключей доступа Windows.";}catch(EntryPointNotFoundException){return "Эта версия Windows не поддерживает сторонних провайдеров ключей доступа. Используйте расширение WinUp.";}catch(DllNotFoundException){return "Системный провайдер доступен только в Windows 11. Используйте расширение WinUp.";}catch(Exception ex){return "Не удалось проверить состояние Windows: "+ex.Message;}}
    }
    sealed class SystemPasskeySetupDialog:Dlg {
        readonly Label status=new Label{AutoSize=true,MaximumSize=new System.Drawing.Size(540,0)};readonly Button install=new Button{Text="Подключить к Windows…",AutoSize=true},remove=new Button{Text="Отключить от Windows",AutoSize=true},refresh=new Button{Text="Проверить состояние",AutoSize=true};bool working;
        internal SystemPasskeySetupDialog():base("Ключи доступа в Windows"){
            Note("После подключения WinUp можно выбирать в системном окне ключей доступа, в том числе при входе в приложения. База WinUp должна быть открыта. Для каждого входа потребуется Windows Hello или пароль базы.");Row("Состояние:",status);
            Note("При первом подключении Windows запросит права администратора для доверия к сертификату WinUp. Для выбора аккаунта Windows получает названия сайтов, имена аккаунтов и идентификаторы ключей. Закрытые ключи и пароли остаются в базе WinUp. При блокировке список аккаунтов убирается из Windows. Подключение относится к текущему пользователю и этой папке WinUp. После переноса программы подключите её заново.");
            var actions=new FlowLayoutPanel{AutoSize=true};actions.Controls.AddRange(new Control[]{install,remove,refresh});Row("Подключение:",actions);var settings=new Button{Text="Открыть параметры Windows",AutoSize=true};Row("Выбор провайдера:",settings);settings.Click+=(s,e)=>{try{Process.Start(new ProcessStartInfo("ms-settings:passkeys-advancedoptions"){UseShellExecute=true});}catch(Exception ex){MessageBox.Show(this,ex.Message,Text);}};
            install.Click+=async(s,e)=>{if(working)return;try{SystemPasskeySetup.EnsureTrusted();await Change(false);}catch(Exception ex){MessageBox.Show(this,ex.Message,Text);UpdateStatus();}};
            remove.Click+=async(s,e)=>{if(!working&&MessageBox.Show(this,"Убрать WinUp из провайдеров Windows? Ключи останутся в базе и продолжат работать через расширение.",Text,MessageBoxButtons.YesNo)==DialogResult.Yes)await Change(true);};refresh.Click+=(s,e)=>{UpdateStatus();var main=Owner as MainForm;if(main!=null)main.RefreshSystemPasskeyCache();};Buttons();Ok.Text="Закрыть";Cancel.Visible=false;UpdateStatus();FormClosing+=(s,e)=>{if(working)e.Cancel=true;};
        }
        void UpdateStatus(){status.Text=SystemPasskeySetup.Status();}
        async System.Threading.Tasks.Task Change(bool delete){working=true;install.Enabled=remove.Enabled=refresh.Enabled=Ok.Enabled=false;status.Text=delete?"Отключение провайдера…":"Подключение провайдера…";try{await System.Threading.Tasks.Task.Run(()=>SystemPasskeySetup.PackageCommand(delete));if(!delete){var main=Owner as MainForm;if(main!=null)main.RefreshSystemPasskeyCache();}}catch(Exception ex){MessageBox.Show(this,ex.Message,Text);}finally{working=false;install.Enabled=remove.Enabled=refresh.Enabled=Ok.Enabled=true;UpdateStatus();}}
    }
}
