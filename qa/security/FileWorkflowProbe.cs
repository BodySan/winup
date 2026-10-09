// Functional tests of real encryption, mounted disk and portable recovery. Synthetic Sandbox data only.
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace WinUp {
    internal static class FileWorkflowProbe {
        const string Password="Synthetic-Files-Workflow-2026!";
        static int passed,failed;
        static void Check(string name,bool result){Console.WriteLine((result?"PASS ":"FAIL ")+name);if(result)passed++;else failed++;}
        static bool Fails(Action action){try{action();return false;}catch(IOException){return true;}}
        [STAThread] static int Main(string[] args){
            Console.SetOut(new StreamWriter(Console.OpenStandardOutput(),new UTF8Encoding(false)){AutoFlush=true});
            bool ci=args.Contains("--ci")&&Environment.GetEnvironmentVariable("GITHUB_ACTIONS")=="true"&&Paths.Root.StartsWith(@"C:\WinUpAudit\",StringComparison.OrdinalIgnoreCase);
            if(Environment.UserName!="WDAGUtilityAccount"&&!ci)throw new Exception("Synthetic Windows Sandbox or isolated GitHub runner only");
            AppDomain.CurrentDomain.AssemblyResolve+=(s,e)=>new AssemblyName(e.Name).Name=="KeePassLib"?CoreLoader.Resolve():EmbeddedModules.Resolve(e.Name);
            string root=Path.Combine(Paths.Root,"files-workflow-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
            if(args.Contains("--ui")){Ui(root);return 0;}
            if(args.Contains("--readonly")){try{ReadOnlyProbe(root);}catch(Exception ex){Console.WriteLine(ex);failed++;}Console.WriteLine("RESULT passed="+passed+" failed="+failed);return failed==0?0:1;}
            try{Run(root);}catch(Exception ex){Console.WriteLine("FAIL exception "+ex);failed++;}
            Console.WriteLine("RESULT passed="+passed+" failed="+failed);return failed==0?0:1;
        }
        static void Run(string root){
            Check("package-name-extension-once",FilePackages.PackageOutputName("example.tar.age")=="example.tar.age"&&FilePackages.PackageOutputName("example")=="example.tar.age"&&FilePackages.PackageOutputName("example.tar")=="example.tar.age");
            var importedService=new LoginEntry{Name="accounts.google.com",Kind="site",Target="https://accounts.google.com/"};
            Check("imported-account-hint-by-template-login-host",AccountOrganization.SameService(importedService,"Google","https://www.google.com/",null,"https://accounts.google.com/login")&&!AccountOrganization.SameService(importedService,"Other","https://other.example/",null,"https://accounts.google.com.evil.example/login"));
            using(var google=PasswordImport.Parse("\uFEFFname,url,username,password,note\r\n\"Тест, сервис\",https://example.com/login,user@example.com,\"  Synthetic,\"\"quoted\"\" password  \",\"строка 1\r\nстрока 2\"\r\n",new LoginEntry[0])){
                var entry=google.Rows[0].Entry;
                Check("google-import-csv-quotes",entry.Name=="Тест, сервис"&&entry.Login=="user@example.com"&&entry.UsePassword(p=>p=="  Synthetic,\"quoted\" password  "));
                Check("google-import-notes-and-login-url",entry.Notes=="строка 1\r\nстрока 2"&&entry.LoginUrl=="https://example.com/login");
                using(var duplicate=PasswordImport.Parse("name,url,username,password\nTest,https://example.com/,user@example.com,\"  Synthetic,\"\"quoted\"\" password  \"",new[]{entry}))Check("password-import-duplicate-skipped",!duplicate.Rows[0].Selectable);
                using(var conflict=PasswordImport.Parse("name,url,username,password\nTest,https://example.com/,user@example.com,Synthetic-new-password",new[]{entry}))Check("password-import-conflict-not-preselected",conflict.Rows[0].Selectable&&!conflict.Rows[0].DefaultSelected);
            }
            using(var apple=PasswordImport.Parse("Title,URL,Username,Password,Notes,OTPAuth\nApple test,https://example.org/,apple@example.com,Synthetic-Apple-password,Note,otpauth://totp/Test:apple?secret=JBSWY3DPEHPK3PXP&issuer=Test",new LoginEntry[0]))Check("apple-import-otp-linked",apple.Rows[0].Entry.Login=="apple@example.com"&&apple.Rows[0].Entry.TwoFa=="link"&&apple.Rows[0].Otp.UseSecret(s=>s=="JBSWY3DPEHPK3PXP"));
            Check("password-import-incomplete-csv",Fails(()=>PasswordImport.Parse("name,url,username,password\n\"unfinished",new LoginEntry[0])));
            string source=Path.Combine(root,"Проект_😀"),small=Path.Combine(source,"Учебный.txt");
            Directory.CreateDirectory(Path.Combine(source,"empty"));Directory.CreateDirectory(Path.Combine(source,"nested"));
            File.WriteAllText(small,"Synthetic file first version",Encoding.UTF8);
            byte[] zone=Encoding.UTF8.GetBytes("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.invalid/fixture\r\n");FilePackages.WriteZone(small,zone);
            using(var large=new FileStream(Path.Combine(source,"nested","large.bin"),FileMode.CreateNew)){byte[] block=Enumerable.Range(0,1024*1024).Select(i=>(byte)(i%251)).ToArray();for(int i=0;i<64;i++)large.Write(block,0,block.Length);}
            string package=Path.Combine(root,"portable.tar.age");FilePackages.Pack(new[]{source},package,Password,false,CancellationToken.None);
            Check("package-age-header",Encoding.ASCII.GetString(File.ReadAllBytes(package).Take(21).ToArray()).StartsWith("age-encryption.org/v1"));
            Check("package-copy-preserves-source",File.Exists(small));
            string output=Path.Combine(root,"device-two");FilePackages.Unpack(package,output,Password,CancellationToken.None);
            string decoded=Path.Combine(output,"Проект_😀","Учебный.txt");Check("package-unicode-content",File.ReadAllText(decoded)==File.ReadAllText(small));
            Check("package-empty-folder",Directory.Exists(Path.Combine(output,"Проект_😀","empty")));
            Check("package-large-file",new FileInfo(Path.Combine(output,"Проект_😀","nested","large.bin")).Length==64L*1024*1024);
            Check("package-download-metadata",zone.SequenceEqual(FilePackages.ReadZone(decoded)));
            FilePackages.Verify(package,Password,CancellationToken.None);Check("package-verify-without-extract",true);
            string bad=Path.Combine(root,"wrong-password");Check("package-wrong-password-no-output",Fails(()=>FilePackages.Unpack(package,bad,"wrong",CancellationToken.None))&&!Directory.Exists(bad));
            Check("package-output-collision-preserves-data",Fails(()=>FilePackages.Unpack(package,output,Password,CancellationToken.None))&&File.ReadAllText(decoded)==File.ReadAllText(small));
            string truncated=Path.Combine(root,"truncated.age");using(var input=File.OpenRead(package))using(var dest=File.Create(truncated)){byte[] block=new byte[65536];long remaining=input.Length-23;while(remaining>0){int n=input.Read(block,0,(int)Math.Min(block.Length,remaining));dest.Write(block,0,n);remaining-=n;}}
            Check("package-truncation-no-output",Fails(()=>FilePackages.Unpack(truncated,Path.Combine(root,"truncated-output"),Password,CancellationToken.None))&&!Directory.Exists(Path.Combine(root,"truncated-output")));
            string moved=Path.Combine(root,"move.txt");File.WriteAllText(moved,"Synthetic move data");FilePackages.Pack(new[]{moved},Path.Combine(root,"move.age"),Password,true,CancellationToken.None);Check("package-verified-move",!File.Exists(moved));
            string collision=Path.Combine(root,"collision.txt");File.WriteAllText(collision,"Synthetic kept source");Check("package-existing-output-keeps-original",Fails(()=>FilePackages.Pack(new[]{collision},package,Password,true,CancellationToken.None))&&File.Exists(collision));
            using(var cancellation=new CancellationTokenSource()){cancellation.CancelAfter(200);bool cancelled=false;try{FilePackages.Pack(new[]{source},Path.Combine(root,"cancelled.age"),Password,true,cancellation.Token);}catch(Exception){cancelled=true;}Check("package-cancel-keeps-original",cancelled&&File.Exists(small)&&!File.Exists(Path.Combine(root,"cancelled.age")));}
            Check("package-cancel-no-staging",!Directory.GetFileSystemEntries(root).Any(x=>Path.GetFileName(x).StartsWith(".winup-package-")));
            string longSource=Path.Combine(root,new string('a',110),new string('b',110));Directory.CreateDirectory(SafePaths.Native(longSource));File.WriteAllText(SafePaths.Native(Path.Combine(longSource,"long.txt")),"Synthetic long path");
            string longPackage=Path.Combine(root,"long-path.age");FilePackages.Pack(new[]{longSource},longPackage,Password,false,CancellationToken.None);FilePackages.Unpack(longPackage,Path.Combine(root,"long-path-result"),Password,CancellationToken.None);
            Check("package-long-source-path",File.ReadAllText(Path.Combine(root,"long-path-result",new string('b',110),"long.txt"))=="Synthetic long path");
            string plain=Path.Combine(root,"plaincopy");PlainFileCopy.Copy(source,plain,CancellationToken.None);Check("ordinary-copy-download-metadata",zone.SequenceEqual(FilePackages.ReadZone(Path.Combine(plain,"Учебный.txt"))));
            string encrypted=Path.Combine(root,"vault");string snapshotId=null;
            using(var client=new FileVaultClient(encrypted,Password,true)){
                string alongside=Path.Combine(root,"package-with-open-vault.tar.age");FilePackages.Pack(new[]{small},alongside,Password,false,CancellationToken.None);FilePackages.Verify(alongside,Password,CancellationToken.None);
                Check("package-while-vault-open",File.Exists(alongside)&&client.Open);
                client.Import(small,"Учебный.txt",false);
                var one=client.Call("snapshot","16777216","3");snapshotId=(string)one["id"];
                Check("history-invisible-in-main-list",((ArrayList)client.Call("list","")["items"]).Count==1);
                client.Call("snapshot","16777216","3");Check("history-unchanged-no-duplicate",((ArrayList)client.Call("history")["items"]).Count==1);
                client.Mount("R:\\");
                string selectedPackage=Path.Combine(root,"selected-only.tar.age");
                var selectedZones=(Dictionary<string,object>)client.Call("zones","Учебный.txt")["zones"];
                Func<string,string> selectedZone=path=>{object value;return selectedZones.TryGetValue(Path.GetFileName(path),out value)?(string)value:null;};
                FilePackages.Pack(new[]{@"R:\Учебный.txt"},selectedPackage,Password,false,CancellationToken.None,selectedZone);
                string selectedOutput=Path.Combine(root,"selected-export");FilePackages.Unpack(selectedPackage,selectedOutput,Password,CancellationToken.None);
                Check("mounted-selection-encrypted-export",File.ReadAllText(Path.Combine(selectedOutput,"Учебный.txt"))==File.ReadAllText(small)&&Directory.GetFiles(selectedOutput,"*",SearchOption.AllDirectories).Length==1);
                Check("mounted-export-preserves-download-metadata",zone.SequenceEqual(FilePackages.ReadZone(Path.Combine(selectedOutput,"Учебный.txt"))));
                File.WriteAllText(@"R:\Учебный.txt","Synthetic edited version",Encoding.UTF8);
                using(var held=new FileStream(@"R:\Учебный.txt",FileMode.Open,FileAccess.ReadWrite,FileShare.Read)){
                    Check("busy-file-detected",client.BusyFiles().Any(x=>x.EndsWith("Учебный.txt")));
                    Check("busy-close-refused-drive-survives",Fails(()=>client.UnmountSafely())&&Directory.Exists("R:\\"));
                }
                client.UnmountSafely();Check("safe-unmount",!Directory.Exists("R:\\"));
                client.Call("snapshot","16777216","3");Check("history-edited-new-version",((ArrayList)client.Call("history")["items"]).Count==2);
                client.Call("delete","Учебный.txt");Check("file-delete",((ArrayList)client.Call("list","")["items"]).Count==0);
                client.Call("history-restore",snapshotId,"Учебный.txt","Восстановлено.txt");
                string restored=Path.Combine(root,"restored.txt");client.Call("export","Восстановлено.txt",restored);
                Check("history-deleted-file-restored",File.ReadAllText(restored)==File.ReadAllText(small));
                Check("history-restored-download-metadata",zone.SequenceEqual(FilePackages.ReadZone(restored)));
                Check("history-restore-collision",Fails(()=>client.Call("history-restore",snapshotId,"Учебный.txt","Восстановлено.txt")));
                client.Call("snapshot","16777216","1");Check("history-retention-limit",((ArrayList)client.Call("history")["items"]).Count==1);
                client.Call("close");
            }
            string backup=Path.Combine(root,"backup-device-two");FilePackages.BackupVault(encrypted,backup,CancellationToken.None);FilePackages.VerifyBackup(backup,CancellationToken.None);Check("backup-checksum-verification",true);
            using(var restored=new FileVaultClient(backup,Password,false,CancellationToken.None,true)){
                var helper=(System.Diagnostics.Process)typeof(FileVaultClient).GetField("process",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(restored);
                helper.ErrorDataReceived+=(s,e)=>{if(e.Data!=null)Console.WriteLine("HELPER "+e.Data);};
                Check("backup-portable-password",((ArrayList)restored.Call("list","")["items"]).Count==1);
                Check("readonly-api-denies-write",Fails(()=>restored.Call("mkdir","forbidden")));
                restored.Mount("R:\\");Check("readonly-explorer-read",File.ReadAllText(@"R:\Восстановлено.txt")==File.ReadAllText(small));
                Check("readonly-explorer-denies-write",Fails(()=>File.WriteAllText(@"R:\forbidden.txt","should fail")));
                try{restored.UnmountSafely();restored.Call("close");}catch{Console.WriteLine("HELPER exited="+helper.HasExited+(helper.HasExited?" code="+helper.ExitCode:""));throw;}
            }
            string backupAgain=Path.Combine(root,"backup-again");FilePackages.BackupVault(backup,backupAgain,CancellationToken.None);FilePackages.VerifyBackup(backupAgain,CancellationToken.None);Check("backup-of-backup",true);
            string saved=Path.Combine(root,"saved-preferences");Directory.CreateDirectory(saved);var pref=new FileVaultPreferences{Drive="R:\\",ReadOnly=true,HistoryMiB=32,HistoryKeep=2,ProjectMode=true,ProjectIdleMinutes=60};pref.Save(saved);var loaded=FileVaultPreferences.Load(saved);
            Check("project-settings-persist",loaded.Drive=="R:\\"&&loaded.ReadOnly&&loaded.ProjectMode&&loaded.ProjectIdleMinutes==60);
            Check("no-plaintext-in-ciphertext-files",!Directory.GetFiles(encrypted,"*",SearchOption.AllDirectories).Any(p=>{byte[] bytes=File.ReadAllBytes(p);return Encoding.UTF8.GetString(bytes).Contains("Synthetic file first version");}));
            Application.EnableVisualStyles();using(var dialog=new FilePackagePasswordDialog(true,true)){Check("package-dialog-default-keeps-originals",!dialog.RemoveOriginals);}
            using(var dialog=new FileImportModeDialog()){Check("import-dialog-default-copy",!dialog.MoveOriginals);}
            using(var dialog=new FileExportModeDialog()){Check("export-dialog-default-encrypted",dialog.Encrypted);}
            var store=new AppStore();store.Settings.WizardDone=true;store.Settings.AutoLockMinutes=1440;store.Settings.HideFromCapture=false;store.Settings.BackupDir=Path.Combine(Paths.Root,"credential-backup");store.Save();
            const BindingFlags flags=BindingFlags.Instance|BindingFlags.NonPublic;
            using(var form=new MainForm(store)) {
                var credentials=KdbxStore.Create(Password,null);
                credentials.Entries.Add(new LoginEntry{Id=AppStore.NewId(),Name="Учебная игра",Kind="site",Target="https://example.com/",Login="player",Password="Synthetic-organized",Pinned=true,Category="Игры"});credentials.Save();
                typeof(MainForm).GetField("vault",flags).SetValue(form,credentials);
                typeof(MainForm).GetMethod("ShowOpen",flags).Invoke(form,null);
                var project=new FileVaultClient(encrypted,Password,false);project.Mount("R:\\");
                typeof(MainForm).GetField("fileVault",flags).SetValue(form,project);
                typeof(MainForm).GetField("filePreferences",flags).SetValue(form,new FileVaultPreferences{History=false});
                typeof(MainForm).GetMethod("LockVaultCore",flags).Invoke(form,new object[]{true});
                Check("credential-lock-keeps-file-drive",form.VaultNow==null&&project.Open&&File.Exists(@"R:\Восстановлено.txt"));
                int left;StoreResult status;credentials=KdbxStore.Open(Password,null,out left,out status);
                Check("pinned-category-kdbx-roundtrip",credentials.Entries.Single().Pinned&&credentials.Entries.Single().Category=="Игры");
                var templates=new[]{new LoginTemplate{Name="Учебная игра",Target="https://example.com/",Category="Игры"}};
                Check("account-category-search-pins",AccountOrganization.Filter(credentials.Entries,templates,"player","Игры",1,true).Count()==1&&AccountOrganization.Filter(credentials.Entries,templates,"player","Дом",1,true).Count()==0);
                Check("existing-account-template-hint",AccountOrganization.SameService(credentials.Entries.Single(),"Учебная игра","https://example.com/login",null));
                typeof(MainForm).GetField("vault",flags).SetValue(form,credentials);
                typeof(MainForm).GetMethod("ShowOpen",flags).Invoke(form,null);
                typeof(MainForm).GetMethod("CloseFileVaultSafely",flags).Invoke(form,null);
                Check("file-lock-keeps-credential-vault",form.VaultNow==credentials&&!Directory.Exists("R:\\"));
                typeof(MainForm).GetMethod("LockVault",flags).Invoke(form,null);
                Check("lock-all-keeps-both-closed",form.VaultNow==null&&typeof(MainForm).GetField("fileVault",flags).GetValue(form)==null);
            }
        }
        static void Ui(string root){
            Console.WriteLine("UI initializing");
            Application.EnableVisualStyles();Directory.CreateDirectory(Paths.Data);
            var store=new AppStore{Templates=Defaults.Load().Templates};store.Settings.WizardDone=true;store.Settings.HideFromCapture=false;store.Settings.AutoLockMinutes=1440;store.Settings.BackupDir=Path.Combine(root,"password-backups");store.Save();
            var vault=KdbxStore.Create(Password,null);
            Console.WriteLine("UI credentials created");
            vault.Entries.Add(new LoginEntry{Id=AppStore.NewId(),Name="Steam Community",Kind="site",Target="https://steamcommunity.com/",Login="Учебный игрок",Password="Synthetic-Steam!",Pinned=true,Category="Игры"});
            vault.Entries.Add(new LoginEntry{Id=AppStore.NewId(),Name="Google",Kind="site",Target="https://accounts.google.com/",Login="user@example.com",Password="Synthetic-Google!",Category="Почта и облако"});vault.Save();
            string folder=Path.Combine(root,"Учебное хранилище");var client=new FileVaultClient(folder,Password,true);
            Console.WriteLine("UI file vault created");
            string source=Path.Combine(root,"Проект");Directory.CreateDirectory(source);File.WriteAllText(Path.Combine(source,"Заметки.txt"),"Учебный проект. Искусственные данные.");client.Import(source,"Проект",false);client.Call("snapshot","16777216","3");
            Console.WriteLine("UI snapshot created");
            var form=new MainForm(store);const BindingFlags flags=BindingFlags.Instance|BindingFlags.NonPublic;
            Console.WriteLine("UI form created");
            typeof(MainForm).GetField("vault",flags).SetValue(form,vault);typeof(MainForm).GetMethod("ShowOpen",flags).Invoke(form,null);
            typeof(MainForm).GetMethod("RememberFileVault",flags).Invoke(form,new object[]{folder});typeof(MainForm).GetField("fileVault",flags).SetValue(form,client);
            var preferences=new FileVaultPreferences{Drive="R:\\",HistoryMiB=16,HistoryKeep=3};preferences.Save(folder);typeof(MainForm).GetField("filePreferences",flags).SetValue(form,preferences);
            form.Shown+=(s,e)=>{typeof(MainForm).GetMethod("RefreshFileItems",flags).Invoke(form,null);};
            File.WriteAllText(Path.Combine(root,"..","ui-ready.json"),new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(new{pid=System.Diagnostics.Process.GetCurrentProcess().Id,root=root,password=Password,vault=folder}));
            Application.Run(form);
        }
        static void ReadOnlyProbe(string root){
            string folder=Path.Combine(root,"vault"),source=Path.Combine(root,"file.txt");File.WriteAllText(source,"Synthetic read-only");
            using(var write=new FileVaultClient(folder,Password,true)){write.Import(source,"file.txt",false);write.Call("close");}
            using(var read=new FileVaultClient(folder,Password,false,CancellationToken.None,true)){
                var helper=(System.Diagnostics.Process)typeof(FileVaultClient).GetField("process",BindingFlags.Instance|BindingFlags.NonPublic).GetValue(read);helper.ErrorDataReceived+=(s,e)=>{if(e.Data!=null)Console.WriteLine("HELPER "+e.Data);};
                read.Mount("R:\\");Check("readonly-quick-read",File.ReadAllText(@"R:\file.txt")=="Synthetic read-only");
                Check("readonly-quick-denies-write",Fails(()=>File.WriteAllText(@"R:\forbidden.txt","Synthetic")));
                try{read.UnmountSafely();Check("readonly-quick-unmount",!Directory.Exists("R:\\"));}catch{Console.WriteLine("EXIT="+(helper.HasExited?helper.ExitCode.ToString():"running"));throw;}
                read.Call("close");
            }
        }
    }
}
