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
            if(args.Contains("--interop")){Interop(root);return 0;}
            if(args.Contains("--routes")){Routes();return 0;}
            if(args.Contains("--ui")){Ui(root);return 0;}
            if(args.Contains("--layout")){Ui(root,true);return 0;}
            if(args.Contains("--readonly")){try{ReadOnlyProbe(root);}catch(Exception ex){Console.WriteLine(ex);failed++;}Console.WriteLine("RESULT passed="+passed+" failed="+failed);return failed==0?0:1;}
            try{Run(root);}catch(Exception ex){Console.WriteLine("FAIL exception "+ex);failed++;}
            Console.WriteLine("RESULT passed="+passed+" failed="+failed);return failed==0?0:1;
        }
        static void Run(string root){
            CheckWaitingAddressUi();
            var apps=new[]{new LocalApplication{Name="ChatGPT",Target=LocalApplications.ShellPrefix+"Synthetic.ChatGPT!App"}};
            var existingApp=new LoginEntry{Name="ChatGPT",Kind="both",Target="https://chatgpt.com/",AppTarget=@"C:\not-installed.exe",Login="demo",Password="Synthetic-only",Args="old"};
            var review=AccountAddressReview.Inspect(existingApp,apps);review.Apply();
            Check("address-review-installed-app-and-route",review.FixApp&&existingApp.AppTarget==apps[0].Target&&existingApp.Args==""&&existingApp.LoginUrl==LoginProfiles.Resolve(existingApp).LoginUrl&&existingApp.UsePassword(p=>p=="Synthetic-only"));
            var custom=new LoginEntry{Name="Custom",Kind="site",Target="https://example.com/",LoginUrl="https://example.com/my-login"};
            Check("address-review-preserves-custom-login-route",!AccountAddressReview.Inspect(custom,apps).FixLogin);
            Check("address-review-rejects-unrelated-login-route",!AccountAddressReview.Inspect(new LoginEntry{Kind="site",Target="https://example.com/",LoginUrl="https://unrelated.example/"},apps).FixLogin);
            Check("address-review-missing-scheme-proposal",AccountAddressReview.Inspect(new LoginEntry{Kind="site",Target="example.com"},apps).Target=="https://example.com");
            Check("address-review-known-site-is-not-wrong-domain",!AccountAddressReview.Inspect(new LoginEntry{Name="Google",Kind="site",Target="https://www.google.com/"},apps).Message.Contains("отличается от шаблона"));
            Check("address-review-known-service-wrong-domain-warning",AccountAddressReview.Inspect(new LoginEntry{Name="Google",Kind="site",Target="https://other.example/"},apps).Message.Contains("отличается от шаблона"));
            var steamLogin=LoginProfiles.Resolve(new LoginEntry{Name="Steam Community",Target="https://steamcommunity.com/"});
            Check("login-profile-saved-account-at-reviewed-login-origin",steamLogin.Id=="Steam Community"&&steamLogin.LoginUrl=="https://steamcommunity.com/login/home/"&&!AccountAddressReview.Inspect(new LoginEntry{Name="Steam Community",Target="https://steamcommunity.com/"},apps).Message.Contains("отличается"));
            var alias=new LoginEntry{Kind="site",Target="https://example.com/",Login="user",Login2="user@example.com",Password="Synthetic"};
            using(var duplicates=PasswordImport.Parse("name,url,username,password\nTest,https://example.com/login,user@example.com,Synthetic\nTest,https://example.com/login,new,Synthetic\nTest,https://example.com/login,new,Synthetic",new[]{alias}))Check("import-existing-alias-and-in-file-duplicates",!duplicates.Rows[0].Selectable&&duplicates.Rows[1].DefaultSelected&&!duplicates.Rows[2].Selectable);
            var googleAccount=new LoginEntry{Kind="both",Target="https://www.google.com/",Login="user@example.com",Password="Synthetic-Google!"};
            using(var family=PasswordImport.Parse("name,url,username,password\nGoogle,https://accounts.google.com/login,user@example.com,Synthetic-Google!\nYouTube,https://www.youtube.com/,user@example.com,Synthetic-Google!\nOther,https://google.com.other.example/,user@example.com,Synthetic-Google!\nOther,https://accounts.google.com:444/,user@example.com,Synthetic-Google!\nOther account,https://accounts.google.com/,other@example.com,Synthetic-Google!",new[]{googleAccount}))Check("import-google-identity-addresses-without-domain-confusion",!family.Rows[0].Selectable&&!family.Rows[1].Selectable&&family.Rows.Skip(2).All(x=>x.DefaultSelected));
            var appleAccount=new LoginEntry{Kind="site",Target="https://www.icloud.com/",Login="apple@example.com",Password="Synthetic-Apple!"};
            using(var family=PasswordImport.Parse("Title,URL,Username,Password\nApple,https://account.apple.com/sign-in,apple@example.com,Synthetic-Apple!\nApple changed,https://appleid.apple.com/,apple@example.com,Synthetic-new!",new[]{appleAccount}))Check("import-apple-identity-addresses-and-conflicting-password",!family.Rows[0].Selectable&&family.Rows[1].Selectable&&!family.Rows[1].DefaultSelected);
            using(var extra=PasswordImport.Parse("name,url,username,password,note\nTest,https://example.com/,user,Synthetic,New note",new[]{alias}))Check("import-same-password-new-notes-not-dropped",extra.Rows[0].Selectable&&!extra.Rows[0].DefaultSelected);
            using(var extra=PasswordImport.Parse("Title,URL,Username,Password,OTPAuth\nTest,https://example.com/,user,Synthetic,otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP",new[]{alias}))Check("import-same-password-new-otp-not-dropped",extra.Rows[0].Selectable&&!extra.Rows[0].DefaultSelected&&extra.Rows[0].Otp!=null);
            using(var sameOtp=PasswordImport.Parse("Title,URL,Username,Password,OTPAuth\nTest,https://example.org/,user,Synthetic,otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP\nTest,https://example.org/,user,Synthetic,otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP",new LoginEntry[0]))Check("import-in-file-duplicate-with-otp-skipped",sameOtp.Rows[0].DefaultSelected&&!sameOtp.Rows[1].Selectable);
            string memoPackage=Path.Combine(root,"Пакет 'учебный'.tar.age");FileInteroperability.WritePackageMemo(memoPackage);string memo=File.ReadAllText(memoPackage+".README.txt");
            Check("independent-guide-filename-quoted-no-secret",memo.Contains("'Пакет ''учебный''.tar.age'")&&!memo.Contains(Password));
            File.WriteAllText(memoPackage+".README.txt","Existing memo");FileInteroperability.WritePackageMemo(memoPackage);
            Check("independent-guide-preserves-existing-memo",File.ReadAllText(memoPackage+".README.txt")=="Existing memo");
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
        static void CheckWaitingAddressUi(){
            var listener=new System.Net.HttpListener();listener.Prefixes.Add("http://localhost:19381/");listener.Start();
            var response=System.Threading.Tasks.Task.Run(async()=>{try{var request=await listener.GetContextAsync();await System.Threading.Tasks.Task.Delay(700);request.Response.StatusCode=200;request.Response.Close();}catch(System.Net.HttpListenerException){}catch(ObjectDisposedException){}});
            try{
                var entry=new LoginEntry{Name="Synthetic delayed site",Kind="site",Target="http://localhost:19381/login",LoginUrl="http://localhost:19381/login"};
                using(var dialog=new AccountAddressDialog(()=>true,x=>false,x=>{},()=>new[]{entry})){
                    dialog.Show();var list=Descendants(dialog).OfType<ListView>().Single();
                    var timeout=DateTime.UtcNow.AddSeconds(12);while(list.Items.Count==0&&DateTime.UtcNow<timeout){Application.DoEvents();Thread.Sleep(20);}if(list.Items.Count!=1)throw new Exception("Address review initialization timeout");
                    list.Items[0].Selected=true;
                    var operation=(System.Threading.Tasks.Task)typeof(AccountAddressDialog).GetMethod("Web",BindingFlags.NonPublic|BindingFlags.Instance).Invoke(dialog,null);
                    Check("address-web-pending-blocks-edit-and-apply",Descendants(dialog).OfType<Button>().Where(b=>b.Text=="Изменить запись…"||b.Text=="Применить отмеченные исправления").All(b=>!b.Enabled));
                    timeout=DateTime.UtcNow.AddSeconds(12);while(!operation.IsCompleted&&DateTime.UtcNow<timeout){Application.DoEvents();Thread.Sleep(20);}if(!operation.IsCompleted)throw new Exception("Address Web status timeout");operation.GetAwaiter().GetResult();
                    Check("address-web-result-and-actions-restored",list.Items[0].SubItems[1].Text.Contains("HTTP 200")&&Descendants(dialog).OfType<Button>().Where(b=>b.Text=="Изменить запись…"||b.Text=="Применить отмеченные исправления").All(b=>b.Enabled));
                    dialog.Close();
                }
            }finally{listener.Stop();listener.Close();}
        }
        static void Interop(string root){
            string source=Path.Combine(root,"Учебные файлы");Directory.CreateDirectory(Path.Combine(source,"Пустая папка"));
            File.WriteAllText(Path.Combine(source,"Заметки.txt"),"Независимая расшифровка. Учебные данные. 😀",new UTF8Encoding(false));
            File.WriteAllBytes(Path.Combine(source,"Binary.bin"),Enumerable.Range(0,8192).Select(i=>(byte)(i%251)).ToArray());
            string package=Path.Combine(root,"Учебный пакет.tar.age");FilePackages.Pack(new[]{source},package,Password,false,CancellationToken.None);FileInteroperability.WritePackageMemo(package);
            string folder=Path.Combine(root,"Cryptomator-vault");using(var client=new FileVaultClient(folder,Password,true)){client.Import(source,"Проект",false);client.Call("close");}
            File.WriteAllText(@"C:\WinUp\test\usability-1.16.1\Как открыть без WinUp.txt",FileInteroperability.All(),new UTF8Encoding(true));
            File.WriteAllText(@"C:\WinUp\test\usability-1.16.1\interop-fixtures.json",new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(new{root=root,source=source,package=package,vault=folder,password=Password}));
            Console.WriteLine("PASS synthetic fixtures created; WinUp clients closed before independent recovery");
        }
        static void Routes(){
            var templates=Defaults.Load().Templates.Where(t=>t.Kind!="app").ToArray();
            var addresses=templates.SelectMany(t=>new[]{t.Target,t.LoginUrl}).Concat(LoginProfiles.All.Select(p=>p.LoginUrl)).Where(x=>LoginProfiles.Origin(x)!=null).Distinct().ToArray();
            var result=new List<object>();var gate=new object();
            System.Threading.Tasks.Parallel.ForEach(addresses,new System.Threading.Tasks.ParallelOptions{MaxDegreeOfParallelism=6},url=>{
                string status=AccountAddressReview.CheckWeb(url,CancellationToken.None);
                lock(gate){result.Add(new{url=url,status=status});Console.WriteLine("CHECK "+result.Count+"/"+addresses.Length+" "+url+" "+status);}
            });
            File.WriteAllText(@"C:\WinUp\test\usability-1.16.1\public-route-checks.json",new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(result),new UTF8Encoding(false));
            Console.WriteLine("PASS checked "+addresses.Length+" public built-in URLs without credentials; HTTP checks do not establish a working login form");
        }
        static void Ui(string root,bool layout=false){
            Console.WriteLine("UI initializing");
            Application.EnableVisualStyles();Directory.CreateDirectory(Paths.Data);
            var store=new AppStore{Templates=Defaults.Load().Templates};store.Settings.WizardDone=true;store.Settings.HideFromCapture=false;store.Settings.AutoLockMinutes=1440;store.Settings.BackupDir=Path.Combine(root,"password-backups");store.Save();
            var vault=KdbxStore.Create(Password,null);
            Console.WriteLine("UI credentials created");
            vault.Entries.Add(new LoginEntry{Id=AppStore.NewId(),Name="Steam Community",Kind="site",Target="https://steamcommunity.com/",Login="Учебный игрок",Password="Synthetic-Steam!",Pinned=true,Category="Игры"});
            vault.Entries.Add(new LoginEntry{Id=AppStore.NewId(),Name="Google",Kind="site",Target="https://www.google.com/",Login="user@example.com",Password="Synthetic-Google!",Category="Почта и облако"});vault.Save();
            string folder=Path.Combine(root,"Учебное хранилище");var client=new FileVaultClient(folder,Password,true);
            Console.WriteLine("UI file vault created");
            string source=Path.Combine(root,"Проект");Directory.CreateDirectory(source);File.WriteAllText(Path.Combine(source,"Заметки.txt"),"Учебный проект. Искусственные данные.");client.Import(source,"Проект",false);client.Call("snapshot","16777216","3");
            Console.WriteLine("UI snapshot created");
            var form=new MainForm(store);const BindingFlags flags=BindingFlags.Instance|BindingFlags.NonPublic;
            Console.WriteLine("UI form created");
            typeof(MainForm).GetField("vault",flags).SetValue(form,vault);typeof(MainForm).GetMethod("ShowOpen",flags).Invoke(form,null);
            typeof(MainForm).GetMethod("RememberFileVault",flags).Invoke(form,new object[]{folder});typeof(MainForm).GetField("fileVault",flags).SetValue(form,client);
            var preferences=new FileVaultPreferences{Drive="R:\\",HistoryMiB=16,HistoryKeep=3};preferences.Save(folder);typeof(MainForm).GetField("filePreferences",flags).SetValue(form,preferences);
            form.Shown+=(s,e)=>{typeof(MainForm).GetMethod("RefreshFileItems",flags).Invoke(form,null);if(layout){var timer=new System.Windows.Forms.Timer{Interval=200};timer.Tick+=(a,b)=>{timer.Stop();try{CheckActionLayout(form);form.Close();}catch(Exception error){Console.WriteLine("FAIL layout "+error);Environment.Exit(1);}finally{timer.Dispose();}};timer.Start();}};
            File.WriteAllText(Path.Combine(root,"..","ui-ready.json"),new System.Web.Script.Serialization.JavaScriptSerializer().Serialize(new{pid=System.Diagnostics.Process.GetCurrentProcess().Id,root=root,password=Password,vault=folder}));
            Application.Run(form);
        }
        static IEnumerable<Control> Descendants(Control control){foreach(Control child in control.Controls){yield return child;foreach(var nested in Descendants(child))yield return nested;}}
        static void CheckActionLayout(MainForm form){
            string shots=@"C:\WinUp\test\usability-1.16.1\shots";Directory.CreateDirectory(shots);
            var tabs=Descendants(form).OfType<TabControl>().First();int checkedButtons=0;
            foreach(var size in new[]{new System.Drawing.Size(700,550),new System.Drawing.Size(1080,760)}){
                form.Size=size;
                foreach(TabPage page in tabs.TabPages){
                    tabs.SelectedTab=page;Application.DoEvents();form.PerformLayout();Application.DoEvents();
                    var area=Descendants(page).OfType<SectionActions>().Single();
                    foreach(var label in Descendants(area).OfType<Label>())if(label.Height<15||label.Width<60)throw new Exception(page.Text+": group caption invisible "+label.Text+" "+label.Bounds);
                    foreach(var button in Descendants(area).OfType<Button>()){
                        area.ScrollControlIntoView(button);Application.DoEvents();
                        var bounds=button.RectangleToScreen(button.ClientRectangle);var viewport=area.RectangleToScreen(area.ClientRectangle);
                        if(!viewport.Contains(bounds))throw new Exception(page.Text+": action clipped "+button.Text+" at "+size+" "+bounds+" outside "+viewport);
                        checkedButtons++;
                    }
                    area.AutoScrollPosition=System.Drawing.Point.Empty;Application.DoEvents();
                    if(size.Width==1080&&area.VerticalScroll.Visible)throw new Exception(page.Text+": full-size actions unnecessarily scroll");
                    var list=Descendants(page).OfType<ListView>().First(v=>v.Visible);
                    if(list.Height<110)throw new Exception(page.Text+": record list too small "+list.Height);
                    if(size.Width==1080){using(var image=new System.Drawing.Bitmap(form.Width,form.Height)){form.DrawToBitmap(image,new System.Drawing.Rectangle(System.Drawing.Point.Empty,form.Size));image.Save(Path.Combine(shots,"117-"+tabs.SelectedIndex+".png"));}}
                    Console.WriteLine("PASS layout "+page.Text+" at "+size+" listHeight="+list.Height);
                }
            }
            Console.WriteLine("PASS layout all "+checkedButtons+" action placements reachable; eight tabs at both window sizes");
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
