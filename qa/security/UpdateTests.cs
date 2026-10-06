using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

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
                    Check("updates-real-dialog-lists-components",dialog.Controls.OfType<ListView>().Single().Items.Count==12,"all bundled modules and KeePass visible");
                    dialog.Close();
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
    }
}
