using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace WinUp {
    static partial class SecurityHarness {
        // Ordinary functional regressions only; no attack/audit suite is called.
        static void DeliveryFilesOnly() {
            try{DeliveryFileTests();}catch(Exception e){Check("delivery-files-unhandled",false,e.ToString());}
            finally{Ui(delegate {form.Close();});}
        }
        static void DeliveryTests() {
            try {
                Ui(delegate {NewVault(true);form.VaultNow.Save();});
                int left;StoreResult result;
                var opened=KdbxStore.Open(Password,null,out left,out result);
                Check("delivery-password-save-reopen",opened!=null && opened.Entries.Single().Login=="audit-user" && opened.Otp.Count==1,"synthetic account and OTP saved together");
                opened.Entries[0].Login2="secondary@example.invalid";
                opened.Entries[0].RecoveryCodes="DEMO-RECOVERY-01\nDEMO-RECOVERY-02";
                opened.Entries[0].Kind="both";
                opened.Save();opened.Lock();
                opened=KdbxStore.Open(Password,null,out left,out result);
                Check("delivery-account-extra-fields-reopen",opened.Entries[0].Login2=="secondary@example.invalid" && opened.Entries[0].UseRecoveryCodes(x=>x.Contains("DEMO-RECOVERY-02")),"secondary login and recovery codes");
                var pin=opened.MakePin("847261");opened.Lock();
                Check("delivery-pin-open",KdbxStore.OpenWithPin("847261",pin,out opened)==StoreResult.Ok && opened!=null,"PIN session in current process");
                string recovery=opened.MakeRecoveryCode();opened.Save();opened.Lock();
                opened=KdbxStore.OpenByRecovery(recovery,out left,out result);
                Check("delivery-recovery-open",opened!=null && opened.Entries.Count==1,"fresh recovery code reopens database");
                opened.SetDbPassword("Synthetic-Changed-2026!",null);opened.Save();opened.Lock();
                opened=KdbxStore.Open("Synthetic-Changed-2026!",null,out left,out result);
                Check("delivery-changed-password-open",opened!=null && opened.Entries[0].Login2=="secondary@example.invalid","password change preserves account");
                string copy=Path.Combine(Paths.Root,"synthetic-export.kdbx");
                Export.CopyEncryptedDatabase(KdbxStore.KdbxFile,copy);
                Check("delivery-encrypted-export",File.ReadAllBytes(copy).SequenceEqual(File.ReadAllBytes(KdbxStore.KdbxFile)),"exact encrypted copy");
                Check("delivery-csv-export",Encoding.UTF8.GetString(Export.Csv(opened.Entries,opened.Otp)).Contains("audit-user"),"synthetic export contents");
                Check("delivery-text-export",Encoding.UTF8.GetString(Export.Text(opened.Entries,opened.Otp)).Contains("audit-user"),"synthetic export contents");
                opened.Lock();
                LocalApplicationTests();
                Ui(delegate {
                    using(var dialog=new PasswordPrompt("Учебный вход","Пароль базы:",7,7,"Открыть кодом")) {
                        dialog.Show(form);Application.DoEvents();
                        var field=dialog.Controls.OfType<TableLayoutPanel>().Single().Controls.OfType<TextBox>().First();
                        var before=field.Bounds;
                        field.Text="Synthetic-Layout-2026!";dialog.PerformLayout();Application.DoEvents();
                        Check("delivery-password-dialog-layout",field.Left==before.Left && field.Width==before.Width && field.Width>=350,"typing preserves field position and width");
                        dialog.Close();
                    }
                });
                Ui(delegate {
                    using(var dialog=new PasskeyConsentDialog("https://example.invalid","synthetic@example.invalid",new List<LoginEntry>())) {
                        dialog.Show(form);Application.DoEvents();
                        var system=dialog.Controls.OfType<TableLayoutPanel>().Single().Controls.OfType<FlowLayoutPanel>().SelectMany(p=>p.Controls.OfType<Button>()).Single(b=>b.Text=="Windows / телефон…");
                        system.PerformClick();Application.DoEvents();
                        Check("delivery-passkey-system-choice",dialog.UseWindows && dialog.DialogResult==DialogResult.Ignore,"explicit system-provider choice preserves native WebAuthn");
                    }
                    var tabs=(TabControl)typeof(MainForm).GetField("tabs",Private).GetValue(form);
                    Check("delivery-tab-order",string.Join("|",tabs.TabPages.Cast<TabPage>().Select(x=>x.Text))=="Пароли|2FA|Ключи доступа|Файлы|Запуск|WinGet|Установка|Скачать","requested order");
                });
                CorrectionUiButtons();MainButtonSweep();InstallerQueueUiTests();BrowserLoginJobTests();
                DeliveryLongPasskeyChallenge();
                DeepBatchStorageTests(Path.Combine(Paths.Root,"transaction-fixtures"));
                DeliveryFileTests();
                var prepared=new ComponentVersionInfo {Id="bouncycastle",Installed="2.6.2",Pending="2.7.0",Latest="2.7.0"};
                ComponentInventory.Availability(prepared);
                Check("delivery-components-pending-status",prepared.Status.Contains("уже подготовлена"),"prepared version is not proposed again");
                prepared.Installed="2.7.0";prepared.Pending=null;ComponentInventory.Availability(prepared);
                Check("delivery-components-current-status",prepared.Status.Contains("не требуется"),"same version after restart");
                var domainList=new ComponentVersionInfo {Id="psl",Installed="2026-10-07_07-09-37_UTC",Latest="2026-10-06_07-09-37_UTC"};
                ComponentInventory.Availability(domainList);
                Check("delivery-components-older-domain-list",domainList.Status.Contains("более новый список") && domainList.Status.Contains("не требуется"),"older official snapshot is not proposed as an update");
                domainList.Pending="2026-10-08_07-09-37_UTC";ComponentInventory.Availability(domainList);
                Check("delivery-components-pending-domain-list",domainList.Status.Contains("уже подготовлен"),"pending newer snapshot is retained");
            }catch(Exception e){Check("delivery-unhandled",false,e.ToString());}
            finally{Ui(delegate {form.Close();});}
        }
        static void DeliveryLongPasskeyChallenge() {
            const string token="synthetic-long-passkey";
            Ui(delegate {NewVault(false);BrowserPair.Save(token,"Synthetic long challenge");});
            var seen=new HashSet<Form>();System.Windows.Forms.Timer timer=null;
            Ui(delegate {
                timer=new System.Windows.Forms.Timer {Interval=100};
                timer.Tick+=delegate {
                    foreach(Form dialog in Application.OpenForms.Cast<Form>().ToArray()) {
                        if(seen.Contains(dialog))continue;
                        if(dialog is PasskeyConsentDialog) {
                            seen.Add(dialog);((Button)typeof(Dlg).GetField("Ok",Private).GetValue(dialog)).PerformClick();
                        } else if(dialog is PasswordPrompt) {
                            seen.Add(dialog);((TextBox)typeof(PasswordPrompt).GetField("box",Private).GetValue(dialog)).Text=Password;
                            ((Button)typeof(Dlg).GetField("Ok",Private).GetValue(dialog)).PerformClick();
                        }
                    }
                };timer.Start();
            });
            try {
                var registration=Request(new {type="passkey-create",token=token,url="https://example.com/login",requestId=Guid.NewGuid().ToString("N"),publicKey=PasskeyOptions(true,"example.com")});
                if(!(bool)registration["ok"])throw new Exception("Synthetic passkey registration failed");
                string challenge=PasskeyPolicy.Encode(Enumerable.Range(0,4096).Select(i=>(byte)(i%251)).ToArray());
                var assertion=Request(new {type="passkey-get",token=token,url="https://example.com/login",requestId=Guid.NewGuid().ToString("N"),publicKey=new {challenge=challenge,rpId="example.com"}});
                Check("delivery-passkey-long-challenge-signs",(bool)assertion["ok"],"4096-byte RP challenge reaches native consent and signs");
                if((bool)assertion["ok"]) {
                    var key=(Dictionary<string,object>)assertion["publicKey"];
                    var response=(Dictionary<string,object>)key["response"];
                    var client=Parse(Encoding.UTF8.GetString(PasskeyPolicy.Decode((string)response["clientDataJSON"],1,16384)));
                    Check("delivery-passkey-long-challenge-preserved",(string)client["challenge"]==challenge,"complete opaque challenge returned in signed client data");
                }
            } finally {Ui(delegate {timer.Dispose();});}
        }
        static void DeliveryFileTests() {
            string root=Path.Combine(Paths.Root,"files-functional");Directory.CreateDirectory(root);
            string source=Path.Combine(root,"Учебная папка"),vault=Path.Combine(root,"encrypted");
            Directory.CreateDirectory(source);Directory.CreateDirectory(Path.Combine(source,"nested"));
            string marker="SYNTHETIC-DOCUMENT-2026";
            File.WriteAllText(Path.Combine(source,"Учебный файл.txt"),marker,Encoding.UTF8);
            File.WriteAllBytes(Path.Combine(source,"nested","binary.bin"),Enumerable.Range(0,200000).Select(x=>(byte)x).ToArray());
            using(var client=new FileVaultClient(vault,"Synthetic-Files-2026!",true)) {
                client.Import(source,"copied",false);
                Check("delivery-files-copy",Directory.Exists(source) && ((ArrayList)client.Call("list","copied")["items"]).Count==2,"folder and nested file copied");
                string exported=Path.Combine(root,"export.txt");client.Call("export","copied/Учебный файл.txt",exported);
                Check("delivery-files-export",File.ReadAllText(exported)==marker,"Unicode name and content round trip");
                client.Import(source,"moved",true);
                Check("delivery-files-move",!Directory.Exists(source) && ((ArrayList)client.Call("list","moved")["items"]).Count==2,"verified move");
                client.Call("mkdir","Новая папка");
                Check("delivery-files-mkdir",((ArrayList)client.Call("list","")["items"]).Cast<Dictionary<string,object>>().Any(x=>(string)x["name"]=="Новая папка"),"Unicode folder visible");
                client.Mount("R:\\");
                File.WriteAllText(@"R:\Проводник.txt",marker,Encoding.UTF8);
                Check("delivery-files-explorer",File.ReadAllText(@"R:\copied\Учебный файл.txt")==marker,"real mounted filesystem");
                client.Call("close");
                Check("delivery-files-unmount",!Directory.Exists("R:\\"),"drive closed");
            }
            using(var client=new FileVaultClient(vault,"Synthetic-Files-2026!",false))
                Check("delivery-files-reopen",((ArrayList)client.Call("list","")["items"]).Count>=3,"reopen persisted vault");
            // Stop immediately after native filesystem writes. The old jfuse
            // teardown freed WinFsp's object while its native loop still ran.
            byte[] payload=Enumerable.Range(0,65537).Select(x=>(byte)(x*17)).ToArray();
            for(int cycle=0;cycle<12;cycle++) {
                using(var client=new FileVaultClient(vault,"Synthetic-Files-2026!",false)) {
                    client.Mount("R:\\");
                    string path=@"R:\write-close-"+cycle+".bin";
                    File.WriteAllBytes(path,payload);
                    client.Call("close");
                    Check("delivery-files-immediate-close-"+cycle,!Directory.Exists("R:\\"),"native loop stops before resources are freed");
                }
                using(var client=new FileVaultClient(vault,"Synthetic-Files-2026!",false)) {
                    string output=Path.Combine(root,"write-close-"+cycle+".bin");
                    client.Call("export","write-close-"+cycle+".bin",output);
                    Check("delivery-files-written-data-"+cycle,File.ReadAllBytes(output).SequenceEqual(payload),"all bytes survive immediate close and reopen");
                    client.Call("close");
                }
            }
        }
    }
}
