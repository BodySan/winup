using System;
using System.IO;
using System.Reflection;
using System.Text;
using System.Linq;
using System.Windows.Forms;

namespace WinUp {
    static class ComponentRuntimeProbe {
        [STAThread] static int Main(string[] args) {
            if(!Paths.Root.StartsWith(@"C:\WinUpAudit\component-runtime",StringComparison.OrdinalIgnoreCase)) throw new Exception("Synthetic isolated component lab only");
            AppDomain.CurrentDomain.AssemblyResolve+=(s,e)=>new AssemblyName(e.Name).Name=="KeePassLib" ? CoreLoader.Resolve() : EmbeddedModules.Resolve(e.Name);
            try {
                if(args[0]=="pending") {
                    string running=ComponentResources.CurrentId;
                    var before=ComponentInventory.Rows().ToDictionary(r=>r.Id,r=>r.Installed);
                    ComponentResources.Store.Install(args[1]);
                    var rows=ComponentInventory.Rows();
                    if(ComponentResources.CurrentId!=running)throw new Exception("Running snapshot changed before restart");
                    foreach(var row in rows.Where(r=>r.Id!="keepass" && r.Id!="winfsp")) {
                        if(row.Installed!=before[row.Id] || row.Pending==null)throw new Exception("Missing separate pending version: "+row.Id);
                        row.Latest=row.Pending;ComponentInventory.Availability(row);
                        if(!row.Status.Contains("уже подготовлена"))throw new Exception("Prepared version offered twice: "+row.Id);
                    }
                    Console.WriteLine("PASS installed-package-keeps-runtime-snapshot-and-all-ten-pending-versions");
                    Application.EnableVisualStyles();
                    using(var dialog=new ComponentUpdatesDialog(null,delegate {},delegate {})) {
                        dialog.Show();Application.DoEvents();
                        var list=dialog.Controls.OfType<ListView>().Single();
                        if(list.Columns.Count!=5 || list.Items.Cast<ListViewItem>().Count(i=>i.SubItems[2].Text!="—")!=10)throw new Exception("Pending versions missing in real UI");
                        var method=typeof(ComponentUpdatesDialog).GetMethod("Installed",BindingFlags.Instance|BindingFlags.NonPublic);method.Invoke(dialog,null);
                        if(!dialog.Controls.OfType<TextBox>().Single().Text.Contains("подготовлен"))throw new Exception("Missing completion history");
                        foreach(var b in dialog.Controls.OfType<FlowLayoutPanel>().Single().Controls.OfType<Button>())if(!b.Visible || b.Bottom>b.Parent.ClientSize.Height)throw new Exception("Update button clipped: "+b.Text);
                        using(var screenshot=new System.Drawing.Bitmap(dialog.Width,dialog.Height)){dialog.DrawToBitmap(screenshot,new System.Drawing.Rectangle(System.Drawing.Point.Empty,dialog.Size));screenshot.Save(@"C:\WinUp\test\corrections\component-pending-ui.png");}
                        dialog.Close();
                    }
                    Console.WriteLine("PASS real-update-dialog-shows-per-component-pending-and-completion-history");return 0;
                }
                if(args[0]=="recheck") {
                    var rows=ComponentInventory.Rows();
                    if(ComponentResources.CurrentId==null || rows.Any(r=>r.Pending!=null))throw new Exception("Restart did not apply staged package");
                    foreach(var row in rows){row.Latest=row.Installed;ComponentInventory.Availability(row);if(!row.Status.Contains("не требуется"))throw new Exception("Installed version offered again: "+row.Id);}
                    Console.WriteLine("PASS fresh-process-applies-package-and-repeat-check-offers-no-installed-version");return 0;
                }
                if(args[0]=="github") {
                    var source=ComponentFeed.Source;
                    if(source!="https://github.com/BodySan/winup/releases/latest/download/") throw new Exception("Unexpected production default source");
                    var release=ComponentFeed.Check(source,System.Threading.CancellationToken.None);
                    if(args.Length>1 && release.sequence!=long.Parse(args[1])) throw new Exception("Unexpected production release sequence "+release.sequence);
                    ComponentFeed.Install(release,source,System.Threading.CancellationToken.None);
                    Console.WriteLine("PASS production-GitHub-feed-signature-download-and-stage sequence="+release.sequence); return 0;
                }
                if(args[0]=="online") {
                    if(!Refuse(delegate { ComponentFeed.Check("https://localhost:9266/bad/",System.Threading.CancellationToken.None); })) throw new Exception("Bad online feed accepted");
                    Console.WriteLine("PASS online-feed-signature-tamper-rejected");
                    var bad=ComponentFeed.Check("https://localhost:9266/tamper/",System.Threading.CancellationToken.None);
                    if(!Refuse(delegate { ComponentFeed.Install(bad,"https://localhost:9266/tamper/",System.Threading.CancellationToken.None); })) throw new Exception("Bad online payload accepted");
                    if(ComponentResources.Store.State().active!=null) throw new Exception("Failed download changed selection");
                    Console.WriteLine("PASS online-package-tamper-preserves-current");
                    var release=ComponentFeed.Check("https://localhost:9266/",System.Threading.CancellationToken.None);
                    ComponentFeed.Install(release,"https://localhost:9266/",System.Threading.CancellationToken.None);
                    Console.WriteLine("PASS real-https-signed-download-and-stage"); return 0;
                }
                if(args[0]=="versions") {
                    var rows=ComponentInventory.Rows(); ComponentInventory.Check(rows,r=>Console.WriteLine(r.Id+" installed="+r.Installed+" latest="+r.Latest+" status="+r.Status));
                    Console.WriteLine("driver="+WinFspDriver.UpdateOfficial(System.Threading.CancellationToken.None)); return 0;
                }
                if(args[0]=="stage") { ComponentResources.Store.Install(args[1]); Console.WriteLine("PASS signed-production-package-staged"); return 0; }
                if(args[0]=="rollback") { ComponentResources.Store.Rollback(); Console.WriteLine("PASS production-package-rollback"); return 0; }
                bool active=ComponentResources.CurrentId!=null;
                if(active!=(args[0]=="active")) throw new Exception("Wrong startup selection");
                Console.WriteLine(active ? "PASS fresh-process-uses-signed-package" : "PASS fresh-process-uses-embedded-baseline");
                if(args[0]=="corrupt" && string.IsNullOrEmpty(ComponentResources.Note)) throw new Exception("Missing corruption warning");
                TestEngines(); return 0;
            } catch(Exception ex) { Console.WriteLine("FAIL "+ex); return 1; }
        }
        static bool Refuse(Action action) { try { action(); return false; } catch(InvalidDataException) { return true; } catch(IOException) { return true; } catch(System.Security.Cryptography.CryptographicException) { return true; } }
        static void TestEngines() {
            if(PasskeyPolicy.ValidRp("github.io","example.github.io")) throw new Exception("PSL not applied");
            string pem; byte[] cose,spki;
            WinUp.PasskeyEngine.Keys.Generate(-7,out pem,out cose,out spki);
            try { if(WinUp.PasskeyEngine.Keys.Sign(pem,new byte[40]).Length<32) throw new Exception("Signing failed"); }
            finally { Secure.Wipe(pem); }
            Console.WriteLine("PASS package-passkey-engine-and-dependencies");
            string root=Path.Combine(Paths.Root,Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root);
            string input=Path.Combine(root,"input.txt"),output=Path.Combine(root,"output.txt");
            File.WriteAllText(input,"synthetic signed package file roundtrip",Encoding.UTF8);
            using(var client=new FileVaultClient(Path.Combine(root,"vault"),"Synthetic-Update-Roundtrip-2026!",true)) {
                client.Import(input,"test.txt",false); client.Call("export","test.txt",output);
                if(!File.ReadAllBytes(input).AsSpanCompatEquals(File.ReadAllBytes(output))) throw new Exception("File roundtrip failed");
            }
            Console.WriteLine("PASS package-file-engine-roundtrip");
        }
        static bool AsSpanCompatEquals(this byte[] a,byte[] b) { if(a.Length!=b.Length) return false; for(int i=0;i<a.Length;i++) if(a[i]!=b[i]) return false; return true; }
    }
}
