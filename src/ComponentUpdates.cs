using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace WinUp {
    internal sealed class ComponentFile {
        public long size { get; set; }
        public string sha256 { get; set; }
    }
    internal sealed class ComponentManifest {
        public int schema { get; set; }
        public int api { get; set; }
        public long sequence { get; set; }
        public string minApp { get; set; }
        public string maxApp { get; set; }
        public Dictionary<string,string> versions { get; set; }
        public Dictionary<string,ComponentFile> files { get; set; }
    }
    internal sealed class ComponentState {
        public string active { get; set; }
        public string previous { get; set; }
        public long highest { get; set; }
    }
    // Raw manifest bytes are signed; no registry hash or package-supplied key grants trust.
    internal sealed class ComponentPackage : IDisposable {
        public const long MaxBytes=256L*1024*1024;
        readonly FileStream held;
        readonly ZipArchive zip;
        readonly object sync=new object();
        public ComponentManifest Manifest { get; private set; }
        public string Id { get; private set; }
        internal ComponentPackage(string path,string publicKey,ComponentManifest baseline,Version app) {
            try {
                SafePaths.NoReparseParents(path);
                held=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
                if(held.Length<1 || held.Length>MaxBytes) throw Bad("Неверный размер пакета.");
                Id=Hash(held); held.Position=0;
                CheckZipDirectory(held,baseline.files.Count+2); held.Position=0;
                zip=new ZipArchive(held,ZipArchiveMode.Read,true);
                var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach(var entry in zip.Entries) {
                    if(!names.Add(entry.FullName) || !AllowedName(entry.FullName) ||
                       ((entry.ExternalAttributes>>16)&0xF000)==0xA000)
                        throw Bad("Повторяющееся или недопустимое имя в пакете.");
                }
                var raw=ReadEntry("manifest.json",1024*1024);
                var signature=ReadEntry("manifest.sig",1024);
                Verify(raw,signature,publicKey);
                Manifest=Json().Deserialize<ComponentManifest>(Encoding.UTF8.GetString(raw));
                ValidateManifest(Manifest,baseline,app);
                var expected=new HashSet<string>(Manifest.files.Keys,StringComparer.Ordinal);
                expected.Add("manifest.json"); expected.Add("manifest.sig");
                if(zip.Entries.Count!=expected.Count || zip.Entries.Any(x=>!expected.Contains(x.FullName)))
                    throw Bad("В пакете есть лишние или отсутствующие файлы.");
                long total=0;
                foreach(var file in Manifest.files) {
                    total=checked(total+file.Value.size);
                    if(total>1024L*1024*1024) throw Bad("Распакованный пакет слишком большой.");
                    var entry=zip.GetEntry(file.Key);
                    if(entry.Length!=file.Value.size) throw Bad("Размер компонента не совпадает.");
                    using(var input=entry.Open()) if(HashExact(input,file.Value.size)!=file.Value.sha256)
                        throw Bad("Контрольная сумма компонента не совпадает: "+file.Key);
                }
            } catch { Dispose(); throw; }
        }
        internal static void ValidateManifest(ComponentManifest m,ComponentManifest baseline,Version app) {
            Version min,max;
            if(m==null || m.schema!=1 || m.api!=baseline.api || m.sequence<1 ||
               !Version.TryParse(m.minApp,out min) || !Version.TryParse(m.maxApp,out max) || min>max || app<min || app>max)
                throw Bad("Комплект несовместим с этой версией WinUp.");
            if(m.files==null || m.versions==null ||
               !new HashSet<string>(m.files.Keys,StringComparer.Ordinal).SetEquals(baseline.files.Keys) ||
               !new HashSet<string>(m.versions.Keys,StringComparer.Ordinal).SetEquals(baseline.versions.Keys))
                throw Bad("Нужен полный согласованный комплект компонентов.");
            foreach(var f in m.files) if(!AllowedName(f.Key) || f.Value==null || f.Value.size<1 || f.Value.size>MaxBytes || !IsHash(f.Value.sha256))
                throw Bad("Неверное описание компонента.");
            foreach(var v in m.versions) if(string.IsNullOrEmpty(v.Value) || v.Value.Length>160 || v.Value.Any(char.IsControl))
                throw Bad("Неверная версия компонента.");
        }
        internal static bool AllowedName(string s) {
            return !string.IsNullOrEmpty(s) && s.Length<180 && !s.StartsWith("/") &&
                !s.Contains("\\") && !s.Contains(":") && s.Split('/').All(p=>p.Length>0 && p!="." && p!="..");
        }
        static void CheckZipDirectory(FileStream file,int count) {
            // Bound central-directory entry count before ZipArchive allocates its entries.
            int size=(int)Math.Min(file.Length,65557); var tail=new byte[size]; file.Position=file.Length-size;
            int offset=0; while(offset<size) { int read=file.Read(tail,offset,size-offset); if(read==0) throw Bad("Оборванный ZIP."); offset+=read; }
            for(int i=size-22;i>=0;i--) if(BitConverter.ToUInt32(tail,i)==0x06054b50 && i+22+BitConverter.ToUInt16(tail,i+20)==size) {
                if(BitConverter.ToUInt16(tail,i+4)!=0 || BitConverter.ToUInt16(tail,i+6)!=0 ||
                    BitConverter.ToUInt16(tail,i+8)!=count || BitConverter.ToUInt16(tail,i+10)!=count) throw Bad("Неверная таблица ZIP-комплекта.");
                return;
            }
            throw Bad("Неверный конец ZIP-комплекта.");
        }
        internal static bool IsHash(string s) { return s!=null && Regex.IsMatch(s,@"\A[a-f0-9]{64}\z"); }
        internal static JavaScriptSerializer Json() { return new JavaScriptSerializer { MaxJsonLength=1024*1024 }; }
        internal static InvalidDataException Bad(string message) { return new InvalidDataException(message); }
        internal static string Hash(Stream stream) { using(var sha=SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","").ToLowerInvariant(); }
        internal static string HashExact(Stream stream,long size) {
            // ZIP's advertised uncompressed length is attacker-controlled. Do not let
            // ComputeHash drain a modified deflate stream beyond the signed length.
            using(var sha=SHA256.Create()) {
                long total=0;var buffer=new byte[81920];int count;
                while((count=stream.Read(buffer,0,(int)Math.Min(buffer.Length,size-total+1)))>0) {
                    total=checked(total+count);if(total>size)throw Bad("Распакованный компонент превышает подписанный размер.");
                    sha.TransformBlock(buffer,0,count,buffer,0);
                }
                if(total!=size)throw Bad("Распакованный компонент оборван.");
                sha.TransformFinalBlock(buffer,0,0);
                return BitConverter.ToString(sha.Hash).Replace("-","").ToLowerInvariant();
            }
        }
        internal static void Verify(byte[] data,byte[] signature,string key) {
            using(var rsa=new RSACryptoServiceProvider()) {
                rsa.PersistKeyInCsp=false; rsa.FromXmlString(key);
                if(rsa.KeySize<3072 || !rsa.VerifyData(data,"SHA256",signature)) throw Bad("Подпись издателя WinUp не прошла проверку.");
            }
        }
        byte[] ReadEntry(string name,long limit) {
            var entry=zip.GetEntry(name);
            if(entry==null || entry.Length<1 || entry.Length>limit) throw Bad("Неверный файл пакета: "+name);
            using(var input=entry.Open()) using(var output=new MemoryStream()) {
                var buffer=new byte[81920]; int read;
                while((read=input.Read(buffer,0,buffer.Length))>0) { if(output.Length+read>limit) throw Bad("Превышен размер файла."); output.Write(buffer,0,read); }
                if(output.Length!=entry.Length) throw Bad("Оборванный файл пакета."); return output.ToArray();
            }
        }
        public Stream Open(string resource) {
            lock(sync) {
                ComponentFile file;
                if(!Manifest.files.TryGetValue(resource,out file)) throw Bad("Неизвестный компонент.");
                var data=ReadEntry(resource,file.size);
                using(var input=new MemoryStream(data)) if(Hash(input)!=file.sha256) throw Bad("Компонент изменён.");
                return new MemoryStream(data,false);
            }
        }
        internal void CopyTo(string path) {
            lock(sync) { held.Position=0; using(var output=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)) { held.CopyTo(output); output.Flush(true); } }
        }
        public void Dispose() { if(zip!=null) zip.Dispose(); if(held!=null) held.Dispose(); }
    }
    internal sealed class ComponentStore {
        readonly string root,key;
        readonly Version app;
        readonly ComponentManifest baseline;
        readonly object sync=new object();
        public ComponentStore(string directory,string publicKey,ComponentManifest embedded,Version application) { root=directory; key=publicKey; baseline=embedded; app=application; }
        string StatePath { get { return Path.Combine(root,"state.json"); } }
        internal ComponentState State() {
            SafePaths.NoReparseParents(StatePath);
            if(!File.Exists(StatePath)) return new ComponentState();
            using(var held=new FileStream(StatePath,FileMode.Open,FileAccess.Read,FileShare.Read)) {
                if(held.Length>4096) throw ComponentPackage.Bad("Повреждено состояние обновлений.");
                using(var reader=new StreamReader(held)) {
                    var state=ComponentPackage.Json().Deserialize<ComponentState>(reader.ReadToEnd());
                    if(state==null || state.highest<0 || state.active!=null && !ComponentPackage.IsHash(state.active) ||
                        state.previous!=null && !ComponentPackage.IsHash(state.previous)) throw ComponentPackage.Bad("Повреждено состояние обновлений.");
                    return state;
                }
            }
        }
        string PackagePath(string id) { if(!ComponentPackage.IsHash(id)) throw ComponentPackage.Bad("Неверный идентификатор пакета."); return Path.Combine(root,"packages",id+".wup"); }
        internal ComponentPackage Inspect(string path) { return new ComponentPackage(path,key,baseline,app); }
        internal ComponentPackage Selected() {
            var state=State(); if(state.active==null) return null;
            var selected=Inspect(PackagePath(state.active));
            if(selected.Id!=state.active) { selected.Dispose(); throw ComponentPackage.Bad("Выбранный пакет подменён."); } return selected;
        }
        internal void Install(string path) {
            lock(sync) using(var package=Inspect(path)) {
                var state=State();
                if(package.Manifest.sequence<=state.highest) throw ComponentPackage.Bad("Этот выпуск уже установлен или старее принятого. Для возврата используйте «Откат».");
                string previous=null;
                if(state.active!=null) try { using(var prior=Inspect(PackagePath(state.active))) if(prior.Id==state.active) previous=state.active; } catch { }
                SafePaths.NoReparseParents(root); Directory.CreateDirectory(root);
                string target=PackagePath(package.Id); SafePaths.NoReparseParents(target); Directory.CreateDirectory(Path.GetDirectoryName(target));
                using(var directoryLease=SourceLease.HoldDirectories(Path.GetDirectoryName(target))) {
                if(File.Exists(target)) { using(var existing=Inspect(target)) if(existing.Id!=package.Id) throw ComponentPackage.Bad("Сохранённый пакет подменён."); }
                else {
                    string temporary=target+"."+Guid.NewGuid().ToString("N")+".partial";
                    try { package.CopyTo(temporary); using(var copied=Inspect(temporary)) if(copied.Id!=package.Id) throw ComponentPackage.Bad("Копия пакета повреждена."); File.Move(temporary,target); }
                    finally { if(File.Exists(temporary)) File.Delete(temporary); }
                }
                Save(new ComponentState { active=package.Id,previous=previous,highest=package.Manifest.sequence });
                }
            }
        }
        internal void Rollback() {
            lock(sync) {
                var state=State();
                if(state.active==null) throw ComponentPackage.Bad("Установленных комплектов для отката нет.");
                if(state.previous!=null) using(var previous=Inspect(PackagePath(state.previous)))
                    if(previous.Id!=state.previous) throw ComponentPackage.Bad("Предыдущий комплект повреждён.");
                using(var directoryLease=SourceLease.HoldDirectories(root))
                    Save(new ComponentState { active=state.previous,previous=null,highest=state.highest });
            }
        }
        void Save(ComponentState state) { SafePaths.NoReparseParents(StatePath); Paths.AtomicWrite(StatePath,Encoding.UTF8.GetBytes(ComponentPackage.Json().Serialize(state))); }
    }
    internal static class ComponentResources {
        static readonly object sync=new object();
        static bool initialized;
        static ComponentPackage selected;
        static ComponentManifest baseline;
        static ComponentStore store;
        public static string Note;
        public static string CurrentId { get { Initialize(); return selected==null ? null : selected.Id; } }
        public static ComponentManifest Current { get { Initialize(); return selected==null ? baseline : selected.Manifest; } }
        public static ComponentManifest Embedded { get { Initialize(); return baseline; } }
        public static ComponentStore Store { get { Initialize(); return store; } }
        internal static void Initialize() {
            lock(sync) {
                if(initialized) return;
                var asm=Assembly.GetExecutingAssembly();
                using(var reader=new StreamReader(asm.GetManifestResourceStream("components.json"))) baseline=ComponentPackage.Json().Deserialize<ComponentManifest>(reader.ReadToEnd());
                string key; using(var reader=new StreamReader(asm.GetManifestResourceStream("component-publisher.xml"))) key=reader.ReadToEnd();
                store=new ComponentStore(Path.Combine(Paths.Data,"components"),key,baseline,asm.GetName().Version);
                try { selected=store.Selected(); } catch(Exception ex) { Note="Комплект компонентов отклонён: "+ex.Message+" Используются встроенные компоненты."; }
                initialized=true;
            }
        }
        public static Stream Open(string resource) {
            Initialize();
            if(selected!=null && selected.Manifest.files.ContainsKey(resource)) return selected.Open(resource);
            return Assembly.GetExecutingAssembly().GetManifestResourceStream(resource);
        }
        public static string Version(string name) { string value; return Current.versions.TryGetValue(name,out value) ? value : "неизвестна"; }
        public static string RuntimeId { get { return CurrentId ?? "embedded-"+Current.files["file-engine.zip"].sha256.Substring(0,16); } }
    }
    internal sealed class ComponentVersionInfo {
        public string Id,Name,Installed,Pending,Latest,Source,Status;
    }
    internal static class ComponentInventory {
        internal static List<ComponentVersionInfo> Rows() {
            var v=ComponentResources.Current.versions;
            var names=new Dictionary<string,string> {
                {"cryptofs","Файловое ядро CryptoFS"},{"cryptolib","Cryptolib"},{"java","Java файлового модуля"},
                {"cli","Комплект Cryptomator CLI"},{"winfsp","Драйвер WinFsp"},{"passkeys","Адаптер ключей доступа WinUp"},
                {"bouncycastle","Bouncy Castle"},{"cbor","CBOR"},{"numbers","Numbers"},{"browser","Расширение WinUp"},{"psl","Список доменных суффиксов"}
            };
            var rows=new List<ComponentVersionInfo> { new ComponentVersionInfo { Id="keepass",Name="Ядро базы KeePass",Installed=KdbxStore.LibVersion(),Status=CoreLoader.Source } };
            foreach(var n in names) rows.Add(new ComponentVersionInfo { Id=n.Key,Name=n.Value,Installed=n.Key=="winfsp" ? WinFspDriver.InstalledVersion : v[n.Key],Status=n.Key=="winfsp" ? "Доступен в комплекте: "+v[n.Key] : "Согласованный комплект" });
            try {
                if(ComponentResources.Store.State().active!=ComponentResources.CurrentId) using(var prepared=ComponentResources.Store.Selected()) {
                    var next=prepared==null ? ComponentResources.Embedded : prepared.Manifest;
                    foreach(var row in rows.Where(r=>r.Id!="keepass" && r.Id!="winfsp")) {
                        string version;if(next.versions.TryGetValue(row.Id,out version))row.Pending=version;
                    }
                }
            }catch(Exception ex) {foreach(var row in rows.Where(r=>r.Id!="keepass" && r.Id!="winfsp"))row.Status="Подготовленное обновление не подтверждено: "+ex.Message;}
            try {
                if(File.Exists(CoreLoader.CoreFile)) {
                    Version version;CoreLoader.ReadVerifiedCore(CoreLoader.CoreFile,out version);
                    if(Newer(rows[0].Installed,version.ToString()))rows[0].Pending=version.ToString();
                }
            }catch(Exception ex) {rows[0].Status="Подготовленное ядро не подтверждено: "+ex.Message;}
            foreach(var row in rows) if(row.Pending!=null) row.Status="Подготовлено; применится после перезапуска";
            return rows;
        }
        internal static void Availability(ComponentVersionInfo row) {
            string effective=row.Pending ?? row.Installed;
            if(row.Latest==null) {if(row.Pending!=null)row.Status="Подготовлено; применится после перезапуска";return;}
            bool newer;
            if(row.Id=="psl") {
                const string stamp=@"\A\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_UTC\z";
                if(!Regex.IsMatch(effective ?? "",stamp) || !Regex.IsMatch(row.Latest,stamp)) {row.Status="Не удалось сравнить формат версии списка доменов";return;}
                int order=string.CompareOrdinal(row.Latest,effective);
                if(order<0) {row.Status=row.Pending==null ? "Используется более новый список; обновление не требуется" : "Более новый список уже подготовлен; перезапустите WinUp";return;}
                newer=order>0;
            } else newer=Newer(effective,row.Latest);
            if(!newer) row.Status=row.Pending==null ? "Проверено: новая версия не требуется" : "Новая версия уже подготовлена; перезапустите WinUp";
            else row.Status=(row.Pending==null ? "" : "Уже подготовлено "+row.Pending+". ")+
                (row.Id=="keepass" || row.Id=="winfsp" ? "Доступно прямое обновление" : "У разработчика есть новый выпуск; для WinUp нужен проверенный совместимый комплект");
        }
        internal static bool Newer(string installed,string latest) {
            var a=Regex.Match(installed ?? "",@"\d+(?:\.\d+){0,3}").Value;
            var b=Regex.Match(latest ?? "",@"\d+(?:\.\d+){0,3}").Value;
            Version av,bv; if(!a.Contains(".")) a+=".0"; if(!b.Contains(".")) b+=".0";
            if(!Version.TryParse(b,out bv))return false;
            if(!Version.TryParse(a,out av))return true;
            av=new Version(av.Major,av.Minor,Math.Max(0,av.Build),Math.Max(0,av.Revision));
            bv=new Version(bv.Major,bv.Minor,Math.Max(0,bv.Build),Math.Max(0,bv.Revision));
            return bv>av;
        }
        internal static string Get(string url,int limit=1024*1024,System.Threading.CancellationToken cancellation=default(System.Threading.CancellationToken)) {
            return Encoding.UTF8.GetString(ComponentNetwork.Fetch(url,limit,cancellation));
        }
        static string Maven(string artifact,System.Threading.CancellationToken cancellation) {
            string xml=Get("https://repo.maven.apache.org/maven2/org/cryptomator/"+artifact+"/maven-metadata.xml",cancellation:cancellation);
            var settings=new System.Xml.XmlReaderSettings { DtdProcessing=System.Xml.DtdProcessing.Prohibit,XmlResolver=null };
            using(var reader=System.Xml.XmlReader.Create(new StringReader(xml),settings)) {
                var document=new System.Xml.XmlDocument { XmlResolver=null }; document.Load(reader);
                var node=document.SelectSingleNode("/metadata/versioning/release"); return node==null ? null : node.InnerText;
            }
        }
        internal static void Check(List<ComponentVersionInfo> rows,Action<ComponentVersionInfo> changed,System.Threading.CancellationToken cancellation=default(System.Threading.CancellationToken)) {
            foreach(var row in rows) {
                cancellation.ThrowIfCancellationRequested();row.Status="Проверяю…";changed(row);
                try {
                    string latest=null;
                    switch(row.Id) {
                        case "keepass": latest=CoreUpdate.ParseLatestVersion(Get(CoreUpdate.HomeUrl,cancellation:cancellation)); if(latest==null) throw new IOException("Официальный сайт не сообщил версию KeePass."); row.Source=CoreUpdate.HomeUrl; break;
                        case "cryptofs": latest=Maven("cryptofs",cancellation); row.Source="https://repo.maven.apache.org/maven2/org/cryptomator/cryptofs/"; break;
                        case "cryptolib": latest=Maven("cryptolib",cancellation); row.Source="https://repo.maven.apache.org/maven2/org/cryptomator/cryptolib/"; break;
                        case "cli": case "winfsp": {
                            string repo=row.Id=="cli" ? "cryptomator/cli" : "winfsp/winfsp";
                            var release=ComponentPackage.Json().Deserialize<Dictionary<string,object>>(Get("https://api.github.com/repos/"+repo+"/releases/latest",cancellation:cancellation));
                            latest=Convert.ToString(release["tag_name"]).TrimStart('v');
                            if(row.Id=="winfsp") {
                                var assets=((System.Collections.IEnumerable)release["assets"]).Cast<Dictionary<string,object>>();
                                var asset=assets.FirstOrDefault(a=>Regex.IsMatch(Convert.ToString(a["name"]),@"\Awinfsp-2\.\d+(?:\.\d+)?\.msi\z",RegexOptions.IgnoreCase));
                                if(asset!=null) latest=Regex.Match(Convert.ToString(asset["name"]),@"\d+(?:\.\d+)+").Value;
                            }
                            row.Source="https://github.com/"+repo+"/releases"; break;
                        }
                        case "bouncycastle": case "cbor": case "numbers": {
                            string package=row.Id=="bouncycastle" ? "bouncycastle.cryptography" : row.Id=="cbor" ? "petero.cbor" : "petero.numbers";
                            var index=ComponentPackage.Json().Deserialize<Dictionary<string,object>>(Get("https://api.nuget.org/v3-flatcontainer/"+package+"/index.json",cancellation:cancellation));
                            latest=((System.Collections.IEnumerable)index["versions"]).Cast<object>().Select(Convert.ToString).Last(x=>!x.Contains("-"));
                            row.Source="https://www.nuget.org/packages/"+package; break;
                        }
                        case "java": row.Status="Обновляется с комплектом Cryptomator CLI"; break;
                        case "psl": {
                            string list=Get("https://publicsuffix.org/list/public_suffix_list.dat",cancellation:cancellation);
                            var version=Regex.Match(list,@"(?m)^// VERSION: (.+)$").Groups[1].Value.Trim();
                            if(version.Length==0) throw new IOException("Источник не сообщил версию списка."); latest=version; row.Source="https://publicsuffix.org/list/public_suffix_list.dat";
                            row.Status=latest==row.Installed ? "Совпадает с официальным списком" : "Доступен другой список; нужен проверенный комплект"; break;
                        }
                        default: row.Status="Собственный код: обновляется с WinUp или подписанным комплектом"; break;
                    }
                    row.Latest=latest;
                    Availability(row);
                } catch(OperationCanceledException) {row.Status="Проверка отменена";throw;} catch(Exception ex) {row.Latest=null;row.Status="Проверка не выполнена: "+ex.Message;}
                changed(row);
            }
        }
    }
}
