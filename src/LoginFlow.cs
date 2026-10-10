using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace WinUp {
    // Rules contain only public URLs and DOM hints. Credentials remain in KDBX.
    public sealed class LoginProfile {
        public string Id { get; set; }
        public string[] Sites { get; set; }
        public string LoginUrl { get; set; }
        public string[] Origins { get; set; }
        public string[] Open { get; set; }
        public string[] OpenSelectors { get; set; }
        public string[] Method { get; set; }
        public string[] MethodSelectors { get; set; }
        public string[] User { get; set; }
        public string[] Password { get; set; }
        public string[] Next { get; set; }
        public string[] NextSelectors { get; set; }
        public string[] Submit { get; set; }
        public string[] SubmitSelectors { get; set; }
        public string[] Otp { get; set; }
        public string Mode { get; set; }
        public string Note { get; set; }
        public string Evidence { get; set; }
    }
    static class LoginProfiles {
        static List<LoginProfile> profiles;
        internal static IEnumerable<LoginProfile> All {
            get {
                if(profiles==null) {
                    using(var stream=ComponentResources.Open("browser/login-profiles.json"))
                    using(var reader=new StreamReader(stream,Encoding.UTF8))
                        profiles=new JavaScriptSerializer().Deserialize<List<LoginProfile>>(reader.ReadToEnd());
                }
                return profiles;
            }
        }
        internal static string Origin(string url) {
            Uri u; if(!Uri.TryCreate(url,UriKind.Absolute,out u) || u.UserInfo.Length!=0 ||
                (u.Scheme!="https" && !(u.Scheme=="http" && u.Host=="localhost"))) return null;
            return u.GetLeftPart(UriPartial.Authority).ToLowerInvariant();
        }
        internal static LoginProfile Resolve(LoginEntry entry) {
            string origin=Origin(entry.Target); if(origin==null) return null;
            var profile=All.FirstOrDefault(p=>p.Id==entry.LoginProfile && (p.Sites.Contains(origin,StringComparer.OrdinalIgnoreCase)||p.Origins.Contains(origin,StringComparer.OrdinalIgnoreCase))) ??
                All.FirstOrDefault(p=>p.Id==AppStore.TemplateName(entry.Name) && (p.Sites.Contains(origin,StringComparer.OrdinalIgnoreCase)||p.Origins.Contains(origin,StringComparer.OrdinalIgnoreCase))) ??
                All.FirstOrDefault(p=>p.Sites.Contains(origin,StringComparer.OrdinalIgnoreCase));
            string route=string.IsNullOrWhiteSpace(entry.LoginUrl) ? profile==null ? entry.Target : profile.LoginUrl : entry.LoginUrl;
            // Older built-in templates copied the site's home URL into LoginUrl.
            // Prefer the reviewed login route in that case; keep custom paths intact.
            if(profile!=null && string.Equals((route ?? "").TrimEnd('/'),(entry.Target ?? "").TrimEnd('/'),StringComparison.OrdinalIgnoreCase)) route=profile.LoginUrl;
            string routeOrigin=Origin(route); if(routeOrigin==null) return null;
            if(profile==null) {
                if(routeOrigin!=origin) return null;
                return new LoginProfile { Id="custom",Sites=new[]{origin},Origins=new[]{origin},LoginUrl=route,Mode="form",Note="Форма определяется на странице. Если она неоднозначна, выберите запись вручную через значок WinUp." };
            }
            if(!profile.Origins.Contains(routeOrigin,StringComparer.OrdinalIgnoreCase)) return null;
            return new LoginProfile { Id=profile.Id,Sites=profile.Sites,Origins=profile.Origins,LoginUrl=route,
                Open=profile.Open,OpenSelectors=profile.OpenSelectors,Method=profile.Method,MethodSelectors=profile.MethodSelectors,User=profile.User,Password=profile.Password,Next=profile.Next,NextSelectors=profile.NextSelectors,Submit=profile.Submit,SubmitSelectors=profile.SubmitSelectors,Otp=profile.Otp,
                Mode=profile.Mode,Note=profile.Note,Evidence=profile.Evidence };
        }
        internal static bool MatchesLoginOrigin(LoginEntry entry,string url) {
            var profile=Resolve(entry);string origin=Origin(url);
            return origin!=null && profile!=null && profile.Mode!="none" && profile.Mode!="manual" && profile.Origins.Contains(origin,StringComparer.OrdinalIgnoreCase);
        }
    }
    partial class MainForm {
        sealed class BrowserLoginJob {
            internal string Nonce,Token,Tab,Target,ProfileId;
            internal LoginProfile Profile;
            internal LoginEntry Entry;
            internal KdbxStore Vault;
            internal int Generation;
            internal DateTime Expires;
            internal HashSet<string> Done=new HashSet<string>();
        }
        readonly Dictionary<string,BrowserLoginJob> browserLogins=new Dictionary<string,BrowserLoginJob>();
        internal string BeginBrowserLogin(LoginEntry entry,bool replaceOutstanding=false) {
            foreach(var key in browserLogins.Where(p=>replaceOutstanding || p.Value.Entry==entry || p.Value.Expires<DateTime.UtcNow || p.Value.Vault!=vault).Select(p=>p.Key).ToArray()) browserLogins.Remove(key);
            if(vault==null || !vault.Entries.Contains(entry)) throw new InvalidOperationException("База закрыта или запись изменена.");
            if(!BrowserSetup.Enabled || BrowserPair.List().Count==0) throw new InvalidOperationException("Подключите и свяжите расширение: Меню → Расширение для браузера. Затем повторите вход.");
            var profile=LoginProfiles.Resolve(entry);
            if(profile==null) throw new InvalidOperationException("Не удалось подтвердить безопасный адрес входа. Проверьте адрес сайта и адрес входа в записи.");
            if(browserLogins.Count>=16) throw new InvalidOperationException("Слишком много незавершённых входов. Подождите три минуты.");
            string nonce=Guid.NewGuid().ToString("N")+Guid.NewGuid().ToString("N");
            var job=new BrowserLoginJob { Nonce=nonce,Entry=entry,Vault=vault,Generation=BrowserGeneration,Target=entry.Target,
                ProfileId=entry.LoginProfile,Profile=profile,Expires=DateTime.UtcNow.AddMinutes(3) };
            browserLogins.Add(nonce,job);
            var uri=new Uri(profile.LoginUrl);
            // The capability is random and carries no account data. Preserve a site's existing hash route.
            string launch=uri.AbsoluteUri+(uri.Fragment.Length==0 ? "#" : "&")+"winup-login="+nonce;
            PwLog(entry.Name+": вход через расширение; "+profile.Note);
            return launch;
        }
        internal string BrowserLoginRequest(string token,string type,string url,string nonce,string tab,string stage) {
            var serializer=new JavaScriptSerializer();
            Func<string,string> fail=e=>serializer.Serialize(new {ok=false,error=e});
            if(string.IsNullOrEmpty(nonce) || nonce.Length!=64 || string.IsNullOrEmpty(tab) || tab.Length>128 || (stage ?? "").Length>64) return fail("bad_request");
            BrowserLoginJob job;
            if(!browserLogins.TryGetValue(nonce,out job)) return fail("not_found");
            if(vault==null || vault!=job.Vault || BrowserGeneration!=job.Generation) { browserLogins.Remove(nonce); return fail("locked"); }
            if(DateTime.UtcNow>job.Expires) { browserLogins.Remove(nonce); return fail("expired"); }
            if(!BrowserPair.IsPaired(token)) return fail("not_paired");
            if(!vault.Entries.Contains(job.Entry) || job.Entry.Target!=job.Target || job.Entry.LoginProfile!=job.ProfileId) { browserLogins.Remove(nonce);return fail("denied"); }
            string origin=LoginProfiles.Origin(url);
            if(origin==null || !job.Profile.Origins.Contains(origin,StringComparer.OrdinalIgnoreCase)) return fail("wrong_origin");
            if(type=="login-claim") {
                Uri incoming,start; if(!Uri.TryCreate(url,UriKind.Absolute,out incoming) || !Uri.TryCreate(job.Profile.LoginUrl,UriKind.Absolute,out start)) return fail("bad_request");
                // HTTP redirects may change the path before a content script can run.
                // The unpredictable capability and the exact reviewed origins bind this claim.
                if(job.Token==null) {
                    job.Token=BrowserPair.HashToken(token);job.Tab=tab;
                }
            }
            if(job.Token!=BrowserPair.HashToken(token) || job.Tab!=tab) return fail("denied");
            if(type=="login-claim") return serializer.Serialize(new {ok=true,profile=job.Profile,autoEnter=job.Entry.AutoEnter,
                hasPassword=job.Entry.UsePassword(p=>!string.IsNullOrEmpty(p)),hasOtp=job.Entry.TwoFa=="link" || job.Entry.TwoFa=="ask",done=job.Done.ToArray(),expiresAt=new DateTimeOffset(job.Expires).ToUnixTimeMilliseconds()});
            if(type=="login-end") {
                browserLogins.Remove(nonce); PwLog(job.Entry.Name+": "+(stage=="filled" ? "поля заполнены; проверьте результат входа в браузере." : "автовход остановлен: "+(stage ?? "отменено")+"."));
                return "{\"ok\":true}";
            }
            if(type!="login-step" || (stage!="user" && stage!="password" && stage!="otp")) return fail("bad_request");
            if(job.Done.Contains(stage)) return fail("already_done");
            if(job.Profile.Mode=="none" || job.Profile.Mode=="manual") return fail("manual");
            // Consume each stage once. Failed/replaced forms require a new explicit login action.
            job.Done.Add(stage);
            if(stage=="user") {
                try{return serializer.Serialize(new {ok=true,login=job.Entry.ResolvedLogin ?? "",login2=job.Entry.ResolvedLogin2 ?? ""});}
                catch(IOException ex){PwLog(job.Entry.Name+": "+ex.Message);return fail("not_found");}
            }
            if(stage=="password") return job.Entry.UsePassword(p=>serializer.Serialize(new {ok=true,password=p ?? ""}));
            string code=null;
            if(job.Entry.TwoFa=="link") {
                var otp=vault.Otp.Find(x=>x.Id==job.Entry.OtpId); if(otp==null) return fail("not_found"); code=Totp.Code(otp);
            } else if(job.Entry.TwoFa=="ask") {
                using(var dialog=new CodeDialog(job.Entry.Name+" — "+origin)) { if(dialog.ShowDialog(this)!=DialogResult.OK) return fail("denied");code=dialog.Code; }
            }
            try {
                if(vault!=job.Vault || BrowserGeneration!=job.Generation) return fail("locked");
                if(!BrowserPair.IsPaired(token)) return fail("not_paired");
                return code==null ? fail("not_found") : serializer.Serialize(new {ok=true,otp=code});
            } finally { Secure.Wipe(code); }
        }
    }
}
