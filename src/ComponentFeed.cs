using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Globalization;
using System.Web.Script.Serialization;

namespace WinUp {
    internal sealed class ComponentRelease {
        public int schema { get; set; }
        public long sequence { get; set; }
        public string package { get; set; }
        public string sha256 { get; set; }
        public long size { get; set; }
        public string expiresUtc { get; set; }
    }
    internal static class ComponentNetwork {
        internal static Uri Https(string value) {
            Uri uri;
            if(!Uri.TryCreate(value,UriKind.Absolute,out uri) || uri.Scheme!="https" || uri.UserInfo.Length!=0 || uri.Fragment.Length!=0)
                throw new IOException("Источник должен быть HTTPS-адресом без пароля и фрагмента.");
            return uri;
        }
        internal static HttpWebResponse Open(string url,CancellationToken cancellation) {
            Uri uri=Https(url);
            try { ServicePointManager.SecurityProtocol|=(SecurityProtocolType)3072; } catch { }
            for(int i=0;i<6;i++) {
                cancellation.ThrowIfCancellationRequested();
                var request=(HttpWebRequest)WebRequest.Create(uri);
                request.AllowAutoRedirect=false; request.Timeout=15000; request.ReadWriteTimeout=15000;
                request.UserAgent="WinUp components";
                HttpWebResponse response;
                try {using(cancellation.Register(request.Abort))response=(HttpWebResponse)request.GetResponse();}
                catch(WebException) {cancellation.ThrowIfCancellationRequested();throw;}
                int code=(int)response.StatusCode;
                if(code==200) return response;
                string location=response.Headers["Location"]; response.Dispose();
                if(code!=301 && code!=302 && code!=303 && code!=307 && code!=308 || string.IsNullOrEmpty(location))
                    throw new IOException("Источник вернул HTTP "+code+".");
                uri=Https(new Uri(uri,location).AbsoluteUri);
            }
            throw new IOException("Слишком много перенаправлений источника.");
        }
        internal static byte[] Fetch(string url,int limit,CancellationToken cancellation) {
            using(var output=new MemoryStream()) { Download(url,output,limit,cancellation); return output.ToArray(); }
        }
        internal static void Download(string url,Stream output,long limit,CancellationToken cancellation) {
            using(var response=Open(url,cancellation)) {
                if(response.ContentLength>limit) throw new IOException("Загрузка слишком большая.");
                using(var input=response.GetResponseStream()) {
                    long total=0; var buffer=new byte[81920]; int read;
                    while((read=input.Read(buffer,0,buffer.Length))>0) {
                        cancellation.ThrowIfCancellationRequested(); total=checked(total+read);
                        if(total>limit) throw new IOException("Загрузка превышает допустимый размер."); output.Write(buffer,0,read);
                    }
                    if(response.ContentLength>=0 && total!=response.ContentLength) throw new IOException("Загрузка оборвалась.");
                }
            }
        }
    }
    internal static class ComponentFeed {
        const string DefaultSource="https://github.com/BodySan/winup/releases/latest/download/";
        static string ConfigPath { get { return Path.Combine(Paths.Data,"components","source.txt"); } }
        public static string Source {
            get { SafePaths.NoReparseParents(ConfigPath); return File.Exists(ConfigPath) ? File.ReadAllText(ConfigPath).Trim() : DefaultSource; }
            set {
                value=(value ?? "").Trim(); if(value.Length>2048) throw new IOException("Адрес слишком длинный.");
                if(value.Length>0) ComponentNetwork.Https(value);
                SafePaths.NoReparseParents(ConfigPath); Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath));
                using(var lease=SourceLease.HoldDirectories(Path.GetDirectoryName(ConfigPath)))
                    Paths.AtomicWrite(ConfigPath,Encoding.UTF8.GetBytes(value.Length>0 ? value.TrimEnd('/')+"/" : ""));
            }
        }
        static string Key() { using(var reader=new StreamReader(System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream("component-publisher.xml"))) return reader.ReadToEnd(); }
        internal static ComponentRelease Check(string source,CancellationToken cancellation) {
            if(string.IsNullOrEmpty(source)) return null;
            source=ComponentNetwork.Https(source).AbsoluteUri.TrimEnd('/')+"/";
            var bytes=ComponentNetwork.Fetch(source+"update.json",65536,cancellation);
            var signature=ComponentNetwork.Fetch(source+"update.sig",1024,cancellation);
            ComponentPackage.Verify(bytes,signature,Key());
            var release=ComponentPackage.Json().Deserialize<ComponentRelease>(Encoding.UTF8.GetString(bytes));
            Validate(release,source,DateTimeOffset.UtcNow);
            return release;
        }
        internal static void Validate(ComponentRelease release,string source,DateTimeOffset now) {
            DateTimeOffset expires;
            if(release==null || release.schema!=1 || release.sequence<1 || release.size<1 || release.size>ComponentPackage.MaxBytes ||
               !ComponentPackage.IsHash(release.sha256) || !DateTimeOffset.TryParse(release.expiresUtc,CultureInfo.InvariantCulture,DateTimeStyles.AssumeUniversal,out expires) ||
               expires<=now || expires>now.AddDays(32) || string.IsNullOrEmpty(release.package))
                throw ComponentPackage.Bad("Описание выпуска неверно или его срок действия истёк.");
            ComponentNetwork.Https(new Uri(new Uri(source),release.package).AbsoluteUri);
        }
        internal static void Install(ComponentRelease release,string source,CancellationToken cancellation,Action<string> progress=null) {
            Validate(release,source,DateTimeOffset.UtcNow);
            if(release.sequence<=ComponentResources.Store.State().highest) throw ComponentPackage.Bad("Этот выпуск уже принят или старее установленного.");
            string folder=Path.Combine(Paths.Data,"components","downloads"); SafePaths.NoReparseParents(folder); Directory.CreateDirectory(folder);
            string path=Path.Combine(folder,Guid.NewGuid().ToString("N")+".partial");
            using(var lease=SourceLease.HoldDirectories(folder)) {
            try {
                if(progress!=null)progress("Скачиваю подписанный комплект №"+release.sequence+"…");
                using(var file=new FileStream(path,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.None)) {
                    ComponentNetwork.Download(new Uri(new Uri(source),release.package).AbsoluteUri,file,release.size,cancellation);
                    if(file.Length!=release.size) throw ComponentPackage.Bad("Размер выпуска не совпадает.");
                    file.Position=0; if(ComponentPackage.Hash(file)!=release.sha256) throw ComponentPackage.Bad("Контрольная сумма выпуска не совпадает."); file.Flush(true);
                }
                if(progress!=null)progress("Проверяю подпись, целостность и совместимость комплекта…");
                using(var inspected=ComponentResources.Store.Inspect(path)) if(inspected.Manifest.sequence!=release.sequence)
                    throw ComponentPackage.Bad("Версия пакета не совпадает с описанием выпуска.");
                cancellation.ThrowIfCancellationRequested();if(progress!=null)progress("Сохраняю проверенный комплект для перезапуска…");ComponentResources.Store.Install(path);
            } finally { if(File.Exists(path)) File.Delete(path); }
            }
        }
    }
}
