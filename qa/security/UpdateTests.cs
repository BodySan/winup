using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using KeePassLib;
using KeePassLib.Cryptography.KeyDerivation;
using KeePassLib.Keys;
using KeePassLib.Serialization;

namespace WinUp {
    static partial class SecurityHarness {
        static string TestPackage(string folder,ComponentManifest manifest,RSACryptoServiceProvider signer,Dictionary<string,byte[]> payload,
            bool badSignature=false,string extra=null,bool duplicate=false) {
            string path=Path.Combine(folder,Guid.NewGuid().ToString("N")+".wup");
            byte[] raw=Encoding.UTF8.GetBytes(ComponentPackage.Json().Serialize(manifest));
            byte[] signature=signer.SignData(raw,"SHA256"); if(badSignature) signature[0]^=1;
            using(var output=File.Create(path)) using(var zip=new ZipArchive(output,ZipArchiveMode.Create)) {
                Action<string,byte[]> put=(name,data)=> { using(var stream=zip.CreateEntry(name).Open()) stream.Write(data,0,data.Length); };
                put("manifest.json",raw); put("manifest.sig",signature);
                foreach(var file in payload) put(file.Key,file.Value);
                if(extra!=null) put(extra,new byte[] {1}); if(duplicate) put(payload.Keys.First(),new byte[] {1});
            }
            return path;
        }
        static ComponentManifest TestManifest(long sequence,Dictionary<string,byte[]> payload) {
            var files=new Dictionary<string,ComponentFile>();
            foreach(var file in payload) using(var input=new MemoryStream(file.Value)) files[file.Key]=new ComponentFile { size=file.Value.Length,sha256=ComponentPackage.Hash(input) };
            return new ComponentManifest { schema=1,api=1,sequence=sequence,minApp="1.13.0.0",maxApp="1.13.999.999",versions=new Dictionary<string,string>{{"test","1"}},files=files };
        }
        static bool Refused(Action action) { try { action(); return false; } catch(InvalidDataException) { return true; } catch(IOException) { return true; } catch(System.Security.Cryptography.CryptographicException) { return true; } }
        static void ComponentUpdateTests() {
            DeepUpdateBoundaryTests();
            KdbxPublicHeaderBoundaryTests();
            string root=Path.Combine(Paths.Root,"update-fixture-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
            using(var key=new RSACryptoServiceProvider(3072)) {
                key.PersistKeyInCsp=false;
                var payload=new Dictionary<string,byte[]> {{"one.dll",Encoding.UTF8.GetBytes("synthetic component")},{"browser/popup.js",Encoding.UTF8.GetBytes("synthetic browser")}};
                var baseline=TestManifest(0,payload); var first=TestManifest(1,payload);
                var store=new ComponentStore(Path.Combine(root,"store"),key.ToXmlString(false),baseline,new Version(1,13,0,0));
                string good=TestPackage(root,first,key,payload);
                using(var inspected=store.Inspect(good)) Check("updates-signed-complete-package",inspected.Manifest.sequence==1,"trusted signature and hashes");
                Check("updates-unsigned-rejected",Refused(()=>store.Install(TestPackage(root,first,key,payload,true))),"no state change");
                var changed=new Dictionary<string,byte[]>(payload); changed["one.dll"]=Encoding.UTF8.GetBytes("tampered component");
                Check("updates-payload-tamper-rejected",Refused(()=>store.Install(TestPackage(root,first,key,changed))),"signed hash mismatch");
                Check("updates-extra-file-rejected",Refused(()=>store.Install(TestPackage(root,first,key,payload,false,"evil.dll"))),"no arbitrary DLLs");
                Check("updates-traversal-rejected",Refused(()=>store.Install(TestPackage(root,first,key,payload,false,"../escape.dll"))),"no extraction outside store");
                Check("updates-duplicate-entry-rejected",Refused(()=>store.Install(TestPackage(root,first,key,payload,false,null,true))),"ambiguous ZIP denied");
                var incomplete=new Dictionary<string,byte[]> {{"one.dll",payload["one.dll"]}};
                Check("updates-incomplete-rejected",Refused(()=>store.Install(TestPackage(root,TestManifest(1,incomplete),key,incomplete))),"cluster must be complete");
                var incompatible=TestManifest(1,payload); incompatible.minApp="9.0"; incompatible.maxApp="10.0";
                Check("updates-app-incompatibility-rejected",Refused(()=>store.Install(TestPackage(root,incompatible,key,payload))),"WinUp version range");
                var wrongApi=TestManifest(1,payload); wrongApi.api=2;
                Check("updates-api-incompatibility-rejected",Refused(()=>store.Install(TestPackage(root,wrongApi,key,payload))),"adapter API version");
                using(var foreign=new RSACryptoServiceProvider(3072)) {
                    foreign.PersistKeyInCsp=false;
                    Check("updates-foreign-publisher-rejected",Refused(()=>store.Install(TestPackage(root,first,foreign,payload))),"package key cannot replace pinned key");
                }
                Check("updates-failed-install-leaves-baseline",store.State().active==null && store.State().highest==0,"all attacks above leave selection intact");
                store.Install(good); string id=store.State().active;
                using(var selected=store.Selected()) using(var input=selected.Open("one.dll"))
                    Check("updates-install-and-load-verified-bytes",new StreamReader(input).ReadToEnd()=="synthetic component","store roundtrip");
                using(var selected=store.Selected()) {
                    bool locked=false; try { File.WriteAllText(Path.Combine(root,"store","packages",id+".wup"),"replaced"); } catch(IOException) { locked=true; }
                    Check("updates-loaded-package-cannot-be-replaced",locked,"held file blocks write/replacement");
                    string next=TestPackage(root,TestManifest(2,payload),key,payload); store.Install(next);
                    Check("updates-current-process-keeps-snapshot",selected.Manifest.sequence==1 && store.State().active!=id,"activation only in next process");
                }
                Check("updates-replay-rejected",Refused(()=>store.Install(good)) && store.State().highest==2,"old signed release denied");
                store.Rollback(); using(var selected=store.Selected()) Check("updates-rollback-to-previous",selected.Manifest.sequence==1 && store.State().highest==2,"explicit rollback keeps high water mark");
                store.Rollback(); Check("updates-rollback-to-embedded",store.Selected()==null && store.State().highest==2,"embedded fallback retained");
                Check("updates-replay-after-rollback-rejected",Refused(()=>store.Install(good)),"network cannot undo user's rollback");
                string third=TestPackage(root,TestManifest(3,payload),key,payload); store.Install(third);
                string damaged=Path.Combine(root,"store","packages",store.State().active+".wup"); File.WriteAllBytes(damaged,new byte[] {0});
                store.Install(TestPackage(root,TestManifest(4,payload),key,payload)); store.Rollback();
                Check("updates-corrupt-previous-falls-back-to-embedded",store.Selected()==null && store.State().highest==4,"damaged/incompatible previous package is not retained for rollback");
                string state=Path.Combine(root,"store","state.json"); File.WriteAllText(state,"{\"active\":\"../outside\"}");
                Check("updates-state-traversal-rejected",Refused(()=>store.Selected()),"only SHA256 identifiers allowed");
                Check("updates-version-comparison",!ComponentInventory.Newer("2.1.25156","2.1") && ComponentInventory.Newer("2.6.2","2.7.0"),"version comparison");
                Check("updates-missing-zero-parts-are-equal",!ComponentInventory.Newer("2.61.1","2.61.1.0") && !ComponentInventory.Newer("2.61.1.0","2.61.1") && !ComponentInventory.Newer("2.1","2.1.0.0"),"release and assembly versions compare consistently");
                var release=new ComponentRelease { schema=1,sequence=1,size=100,sha256=new string('a',64),package="component.wup",expiresUtc=DateTimeOffset.UtcNow.AddDays(7).ToString("o") };
                ComponentFeed.Validate(release,"https://example.test/releases/",DateTimeOffset.UtcNow);
                release.expiresUtc=DateTimeOffset.UtcNow.AddDays(-1).ToString("o");
                Check("updates-expired-feed-rejected",Refused(()=>ComponentFeed.Validate(release,"https://example.test/releases/",DateTimeOffset.UtcNow)),"freeze/replay bound");
                release.expiresUtc=DateTimeOffset.UtcNow.AddDays(7).ToString("o"); release.package="http://example.test/component.wup";
                Check("updates-http-download-rejected",Refused(()=>ComponentFeed.Validate(release,"https://example.test/releases/",DateTimeOffset.UtcNow)),"HTTPS enforced");
                Check("updates-source-credentials-rejected",Refused(()=>ComponentNetwork.Https("https://user:secret@example.test/")),"no secrets in URL");
                string zip=Path.Combine(root,"truncated.wup"); File.WriteAllBytes(zip,File.ReadAllBytes(good).Take(100).ToArray());
                Check("updates-truncated-package-rejected",Refused(()=>store.Inspect(zip)),"current selection remains intact");
            }
            Ui(delegate {
                using(var dialog=new ComponentUpdatesDialog(null,delegate {},delegate {})) {
                    dialog.Show(form); Application.DoEvents();
                    var rows=dialog.Controls.OfType<ListView>().Single().Items.Cast<ListViewItem>().Select(item=>((ComponentVersionInfo)item.Tag).Id).ToArray();
                    var expected=ComponentResources.Current.versions.Keys.Concat(new[]{"keepass"}).ToArray();
                    Check("updates-real-dialog-lists-components",rows.Length==expected.Length&&new HashSet<string>(rows).SetEquals(expected),"exact bundled component identities plus KeePass; no obsolete fixed row count");
                    dialog.Close();
                }
                string cancelResult=null;
                using(var dialog=new ComponentUpdatesDialog(text=>cancelResult=text,delegate {},delegate {})) {
                    dialog.Show(form);Application.DoEvents();
                    var run=typeof(ComponentUpdatesDialog).GetMethod("Run",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic);
                    run.Invoke(dialog,new object[] {new Action<CancellationToken>(token=>{token.WaitHandle.WaitOne();token.ThrowIfCancellationRequested();}),null});
                    dialog.Close();
                    var until=DateTime.UtcNow.AddSeconds(5);while(dialog.Visible && DateTime.UtcNow<until){Application.DoEvents();Thread.Sleep(10);}
                    Check("updates-close-cancels-operation-and-closes-dialog",!dialog.Visible && cancelResult!=null && cancelResult.Contains("отменена"),"actual close event cancels worker and preserves completion status");
                }
                string path=Path.Combine(Paths.Data,"components","state.json");
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                byte[] previous=File.Exists(path) ? File.ReadAllBytes(path) : null;
                try {
                    File.WriteAllText(path,"{\"active\":\"../outside\"}");
                    using(var dialog=new ComponentUpdatesDialog(null,delegate {},delegate {})) {
                        dialog.Show(form); Application.DoEvents();
                        Check("updates-corrupt-state-dialog-survives",dialog.Controls.OfType<Label>().Single().Text.Contains("повреждено"),"damaged selection reports error without crashing"); dialog.Close();
                    }
                } finally { if(previous==null) File.Delete(path); else File.WriteAllBytes(path,previous); }
            });
        }
        static void DeepUpdateBoundaryTests() {
            Check("core-update-running-version-downgrade-denied",Refused(()=>CoreUpdate.RequireCurrentOrNewer(new Version(2,60,0,0),new Version(2,61,1,0))),"older signed core cannot replace a newer running release");
            Check("core-update-prepared-version-downgrade-denied",Refused(()=>CoreUpdate.RequireCurrentOrNewer(new Version(2,61,1,0),new Version(2,62,0,0))),"a second update cannot overwrite a newer prepared core");
            CoreUpdate.RequireCurrentOrNewer(new Version(2,61,1,0),new Version(2,61,1,0));
            Check("core-update-same-version-repair-allowed",true,"verified same version may repair damaged staging");
            byte[] many;
            using(var memory=new MemoryStream()) {
                using(var archive=new ZipArchive(memory,ZipArchiveMode.Create,true))
                    for(int i=0;i<=CoreUpdate.MaxArchiveEntries;i++)archive.CreateEntry("entry-"+i);
                many=memory.ToArray();
            }
            Check("core-update-entry-count-bomb-denied",Refused(()=>CoreUpdate.ValidateArchiveDirectory(many)),"directory bound enforced before ZipArchive allocates entries");
            Check("core-update-truncated-directory-denied",Refused(()=>CoreUpdate.ValidateArchiveDirectory(new byte[64])),"missing ZIP end record rejected");
            byte[] duplicate;
            using(var memory=new MemoryStream()) {
                using(var archive=new ZipArchive(memory,ZipArchiveMode.Create,true)) {
                    using(var output=archive.CreateEntry("KeePass.exe").Open())output.WriteByte(1);
                    using(var output=archive.CreateEntry("keepass.EXE").Open())output.WriteByte(1);
                }
                duplicate=memory.ToArray();
            }
            string error;
            Check("core-update-ambiguous-candidate-denied",!CoreUpdate.StageSignedPackage(duplicate,"2.61.1",out error) && error.Contains("однозначного"),"case-variant duplicate core is rejected before publisher verification");
            Check("core-update-invalid-request-version-denied",!CoreUpdate.StageSignedPackage(duplicate,"2.61.1\n",out error) && error.Contains("Неверная версия"),"newline cannot bypass exact version validation");
            Check("installer-system-tools-use-absolute-paths",Path.IsPathRooted(InstallForm.SystemTool("msiexec.exe")) && InstallForm.SystemTool("taskkill.exe")==Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"taskkill.exe"),"installer-folder/PATH executables are not selected");
            using(var oversized=new MemoryStream(new byte[1024*1024])) {
                bool denied=Refused(()=>ComponentPackage.HashExact(oversized,16));
                Check("updates-decompression-hash-is-bounded",denied && oversized.Position==17,"stop after signed length plus one byte, not after attacker-controlled deflate EOF");
            }
            using(var truncated=new MemoryStream(new byte[15]))
                Check("updates-decompressed-truncation-denied",Refused(()=>ComponentPackage.HashExact(truncated,16)),"exact signed length required");
            var good=Encoding.UTF8.GetBytes("bounded signed bytes");
            using(var bounded=new MemoryStream(good))using(var original=new MemoryStream(good))
                Check("updates-bounded-hash-preserves-sha256",ComponentPackage.HashExact(bounded,good.Length)==ComponentPackage.Hash(original),"hash is unchanged for valid exact-length streams");
        }
        static KdfParameters SafetyKdf() {
            var parameters=new Argon2Kdf().GetDefaultParameters();
            parameters.SetUInt64(Argon2Kdf.ParamMemory,64UL<<20);
            parameters.SetUInt64(Argon2Kdf.ParamIterations,8);
            parameters.SetUInt32(Argon2Kdf.ParamParallelism,2);
            parameters.SetByteArray(Argon2Kdf.ParamSalt,new byte[32]);
            return parameters;
        }
        static byte[] SafetyKdbxFixture(byte[] dictionary,int blockSize=0,byte[] publicData=null) {
            using(var memory=new MemoryStream())using(var writer=new BinaryWriter(memory,Encoding.UTF8,true)) {
                writer.Write(0x9AA2D903U);writer.Write(0xB54BFB67U);writer.Write(0x00040000U);
                Action<byte,byte[]> field=(id,data)=>{writer.Write(id);writer.Write(data.Length);writer.Write(data);};
                field(2,new byte[16]);field(3,new byte[4]);field(4,new byte[32]);field(7,new byte[16]);field(11,dictionary);
                if(publicData!=null)field(12,publicData);
                field(0,new byte[]{13,10,13,10});writer.Flush();
                byte[] digest;using(var hash=SHA256.Create())digest=hash.ComputeHash(memory.ToArray());
                writer.Write(digest);writer.Write(new byte[32]);writer.Write(new byte[32]);writer.Write(blockSize);writer.Flush();
                return memory.ToArray();
            }
        }
        static void KdbxPublicHeaderBoundaryTests() {
            var parameters=SafetyKdf();var normal=SafetyKdbxFixture(KdfParameters.SerializeExt(parameters));
            using(var memory=new MemoryStream(normal))KdbxSafety.Validate(memory);
            Check("kdbx-bounded-header-preflight",true,"public KDBX4 structure checked without deriving a key");
            Action<KdfParameters,string> reject=(bad,name)=> {
                var bytes=SafetyKdbxFixture(KdfParameters.SerializeExt(bad));
                using(var memory=new MemoryStream(bytes))Check(name,Refused(()=>KdbxSafety.Validate(memory)),"rejected before untrusted Argon2 allocation/iterations");
            };
            parameters=SafetyKdf();parameters.SetUInt64(Argon2Kdf.ParamMemory,1UL<<30);reject(parameters,"kdbx-attacker-memory-budget-denied");
            parameters=SafetyKdf();parameters.SetUInt64(Argon2Kdf.ParamIterations,ulong.MaxValue);reject(parameters,"kdbx-attacker-iterations-budget-denied");
            parameters=SafetyKdf();parameters.SetUInt32(Argon2Kdf.ParamParallelism,uint.MaxValue);reject(parameters,"kdbx-attacker-thread-budget-denied");
            parameters=SafetyKdf();parameters.SetUInt64(Argon2Kdf.ParamMemory,512UL<<20);parameters.SetUInt64(Argon2Kdf.ParamIterations,1024);reject(parameters,"kdbx-combined-argon-work-budget-denied");
            parameters=SafetyKdf();parameters.SetUInt64(Argon2Kdf.ParamMemory,512UL<<20);parameters.SetUInt64(Argon2Kdf.ParamIterations,128);KdbxSafety.ValidateKdfParameters(parameters);
            Check("kdbx-maximum-supported-argon-work-allowed",true,"512 MiB and128 iterations accepted without executing KDF");
            byte[] legacy=(byte[])normal.Clone();Buffer.BlockCopy(BitConverter.GetBytes(0x00030001U),0,legacy,8,4);
            using(var memory=new MemoryStream(legacy))Check("kdbx3-requires-explicit-conversion",Refused(()=>KdbxSafety.Validate(memory)),"legacy encrypted block lengths cannot be preflighted safely");
            byte[] giant=(byte[])normal.Clone();Buffer.BlockCopy(BitConverter.GetBytes(int.MaxValue),0,giant,13,4);
            using(var memory=new MemoryStream(giant))Check("kdbx-attacker-header-allocation-denied",Refused(()=>KdbxSafety.Validate(memory)),"2 GiB declared field refused before byte[] allocation");
            byte[] badDictionary;
            using(var memory=new MemoryStream())using(var writer=new BinaryWriter(memory)) {
                writer.Write((ushort)0x100);writer.Write((byte)66);writer.Write(int.MaxValue);badDictionary=memory.ToArray();
            }
            var nested=SafetyKdbxFixture(KdfParameters.SerializeExt(SafetyKdf()),0,badDictionary);
            using(var memory=new MemoryStream(nested))Check("kdbx-attacker-nested-allocation-denied",Refused(()=>KdbxSafety.Validate(memory)),"2 GiB VariantDictionary name refused before KeePass deserializer");
            var badBlock=SafetyKdbxFixture(KdfParameters.SerializeExt(SafetyKdf()),int.MaxValue);
            using(var memory=new MemoryStream(badBlock))Check("kdbx-attacker-block-allocation-denied",Refused(()=>KdbxSafety.Validate(memory)),"2 GiB unauthenticated HMAC block length refused");
            byte[] truncated=normal.Take(normal.Length-1).ToArray();
            using(var memory=new MemoryStream(truncated))Check("kdbx-truncated-public-block-denied",Refused(()=>KdbxSafety.Validate(memory)),"truncated terminator rejected before KDF");
            byte[] digestChanged=(byte[])normal.Clone();digestChanged[21]^=1;
            using(var memory=new MemoryStream(digestChanged))Check("kdbx-public-header-digest-denied",Refused(()=>KdbxSafety.Validate(memory)),"cheap public checksum checked before key derivation");
            string path=Path.Combine(Paths.Root,"safety-roundtrip.kdbx");
            var key=new CompositeKey();key.AddUserKey(new KcpPassword("Synthetic-Safety-2026!"));
            var database=new PwDatabase();database.New(IOConnectionInfo.FromPath(path),key);
            var fast=SafetyKdf();fast.SetUInt64(Argon2Kdf.ParamMemory,8192);fast.SetUInt64(Argon2Kdf.ParamIterations,1);fast.SetUInt32(Argon2Kdf.ParamParallelism,1);
            database.KdfParameters=fast;database.Save(null);database.Close();
            var reopened=new PwDatabase();
            try {
                KdbxSafety.OpenDatabase(reopened,path,key,null);
                Check("kdbx-real-safe-open-roundtrip",reopened.IsOpen,"actual KeePass4 encrypted database opens through held preflight wrapper");
            }finally {reopened.Close();if(File.Exists(path))File.Delete(path);}
        }
    }
}
