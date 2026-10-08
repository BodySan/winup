using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Keys = WinUp.PasskeyEngine.Keys;

namespace WinUp {
    internal static class PasskeyPolicy {
        static readonly HashSet<string> exact=new HashSet<string>(), wildcard=new HashSet<string>(), exceptions=new HashSet<string>();
        static PasskeyPolicy() {
            using(var reader=new StreamReader(ComponentResources.Open("public-suffix-list.dat"))) {
                string line;
                while((line=reader.ReadLine())!=null) {
                    line=line.Trim(); if(line.Length==0 || line.StartsWith("//")) continue;
                    bool except=line[0]=='!', wild=line.StartsWith("*.");
                    string domain=Ascii(except ? line.Substring(1) : wild ? line.Substring(2) : line);
                    (except ? exceptions : wild ? wildcard : exact).Add(domain);
                }
            }
        }
        static string Ascii(string s) { return new IdnMapping().GetAscii(s).ToLowerInvariant(); }
        // The same complete PSL (including private hosting domains) also protects
        // password matching. Unknown TLDs use the PSL's prevailing "*" rule.
        internal static string Registrable(string host) {
            try {
                host=Ascii(host.TrimEnd('.'));
                if(Uri.CheckHostName(host)!=UriHostNameType.Dns || host=="localhost" || host.EndsWith(".localhost",StringComparison.Ordinal)) return host;
                var labels=host.Split('.'); int suffix=SuffixLength(labels);
                return labels.Length>suffix ? string.Join(".",labels.Skip(labels.Length-suffix-1)) : host;
            } catch { return null; }
        }
        static int SuffixLength(string[] labels) {
            int suffix=1;
            for(int i=0;i<labels.Length;i++) {
                string tail=string.Join(".",labels.Skip(i));
                if(exceptions.Contains(tail)) return labels.Length-i-1;
                if(exact.Contains(tail)) suffix=Math.Max(suffix,labels.Length-i);
                if(i>0 && wildcard.Contains(tail)) suffix=Math.Max(suffix,labels.Length-i+1);
            }
            return suffix;
        }
        public static bool ValidRp(string rp,string host) {
            if(string.IsNullOrEmpty(rp) || rp.Length>253 || rp.EndsWith(".") || rp.IndexOfAny(new[] {'/',':','\\','@',' '})>=0) return false;
            try { rp=Ascii(rp); host=Ascii(host); } catch { return false; }
            if(Uri.CheckHostName(rp)!=UriHostNameType.Dns) return false;
            if(host!=rp && !host.EndsWith("."+rp,StringComparison.Ordinal)) return false;
            if(rp=="localhost") return host==rp;
            var labels=rp.Split('.');
            return labels.Length>SuffixLength(labels);
        }
        public static string Origin(string url,out string host) {
            host=null; Uri uri;
            if(!Uri.TryCreate(url,UriKind.Absolute,out uri) || uri.UserInfo.Length!=0) return null;
            if(uri.Scheme!="https" && !(uri.Scheme=="http" && uri.Host=="localhost")) return null;
            host=uri.IdnHost.ToLowerInvariant();
            return uri.GetLeftPart(UriPartial.Authority);
        }
        public static string Encode(byte[] b) { return Convert.ToBase64String(b).TrimEnd('=').Replace('+','-').Replace('/','_'); }
        public static byte[] Decode(string s,int min,int max) {
            if(s==null || s.Length>max*2 || s.Any(c=>!char.IsLetterOrDigit(c) && c!='-' && c!='_')) throw new FormatException("invalid_binary");
            string b=s.Replace('-','+').Replace('_','/');
            byte[] bytes=Convert.FromBase64String(b+new string('=',(4-b.Length%4)%4));
            if(bytes.Length<min || bytes.Length>max) throw new FormatException("invalid_binary_length");
            return bytes;
        }
    }
    partial class MainForm {
        static string PString(Dictionary<string,object> d,string key,string fallback="") { object value; return d!=null && d.TryGetValue(key,out value) ? value as string ?? fallback : fallback; }
        static Dictionary<string,object> PObject(Dictionary<string,object> d,string key) { object value; return d!=null && d.TryGetValue(key,out value) ? value as Dictionary<string,object> : null; }
        static IEnumerable<Dictionary<string,object>> PArray(Dictionary<string,object> d,string key) {
            object value; var list=d!=null && d.TryGetValue(key,out value) ? value as IEnumerable : null;
            return list==null ? Enumerable.Empty<Dictionary<string,object>>() : list.Cast<object>().OfType<Dictionary<string,object>>();
        }
        static Dictionary<string,object>[] PDescriptors(Dictionary<string,object> options,string key) {
            object value;
            if(!options.TryGetValue(key,out value)) return new Dictionary<string,object>[0];
            var list=value as IList;
            if(list==null || list.Count>100) throw new FormatException("invalid_credentials");
            var result=new List<Dictionary<string,object>>();
            foreach(object item in list) {
                var descriptor=item as Dictionary<string,object>;
                if(descriptor==null || PString(descriptor,"type")!="public-key") throw new FormatException("invalid_credential");
                PasskeyPolicy.Decode(PString(descriptor,"id"),1,1024);
                result.Add(descriptor);
            }
            return result.ToArray();
        }
        static string PasskeyError(string name) { return new JavaScriptSerializer().Serialize(new { ok=false,error=name }); }
        internal string BrowserPasskey(string url,bool create,Dictionary<string,object> options,Func<bool> cancelled) {
            var current=vault; if(current==null) return PasskeyError("locked");
            string host; string origin=PasskeyPolicy.Origin(url,out host);
            if(origin==null || options==null) return PasskeyError("SecurityError");
            string rp=create ? PString(PObject(options,"rp"),"id",host) : PString(options,"rpId",host);
            if(!PasskeyPolicy.ValidRp(rp,host)) return PasskeyError("SecurityError");
            rp=new IdnMapping().GetAscii(rp).ToLowerInvariant();
            byte[] challenge; string userId=null, userName=null; int algorithm=0;
            try {
                // Google account verification uses a challenge of several KB.
                // It is opaque RP data; do not confuse its size with a credential
                // ID. Keep a bounded size within the browser message limit.
                challenge=PasskeyPolicy.Decode(PString(options,"challenge"),16,8192);
                if(create) {
                    var user=PObject(options,"user"); userId=PString(user,"id");
                    PasskeyPolicy.Decode(userId,1,64); userName=PString(user,"name");
                    if(userName.Length==0 || userName.Length>256) return PasskeyError("TypeError");
                    foreach(var param in PArray(options,"pubKeyCredParams")) {
                        object value;
                        if(PString(param,"type")!="public-key" || !param.TryGetValue("alg",out value)) continue;
                        int a=Convert.ToInt32(value); if(a==-7 || a==-8 || a==-257) { algorithm=a; break; }
                    }
                    if(algorithm==0) return PasskeyError("NotSupportedError");
                    if(PString(options,"attestation")=="enterprise") return PasskeyError("NotSupportedError");
                }
                var ext=PObject(options,"extensions");
                // Optional unsupported WebAuthn extensions are ignored. Never report PRF/largeBlob
                // results that the software authenticator did not produce. Every operation uses UV.
            } catch { return PasskeyError("TypeError"); }
            var candidates=current.Entries.Where(e=>e.Kind=="passkey" && e.Target==rp).ToList();
            Dictionary<string,object>[] allowed;
            try { allowed=PDescriptors(options,create ? "excludeCredentials" : "allowCredentials"); }
            catch { return PasskeyError("TypeError"); }
            if(create && candidates.Any(e=>allowed.Any(a=>PString(a,"id")==e.Args))) return PasskeyError("InvalidStateError");
            if(!create && allowed.Length>0) candidates=candidates.Where(e=>allowed.Any(a=>PString(a,"type")=="public-key" && PString(a,"id")==e.Args)).ToList();
            if(!create && candidates.Count==0) return PasskeyError("not_found");
            if(cancelled()) return PasskeyError("AbortError");
            LoginEntry selected=null;
            using(var prompt=new PasskeyConsentDialog(origin,create ? userName : null,candidates)) {
                using(var timer=new Timer { Interval=100 }) {
                    timer.Tick+=(s,e)=> { if(cancelled() || vault!=current) prompt.Close(); }; timer.Start();
                    Win.Focus(Handle);
                    var result=prompt.ShowDialog(this);
                    if(prompt.UseWindows && !cancelled() && vault==current) return "{\"ok\":false,\"fallback\":true}";
                    if(result!=DialogResult.OK) return PasskeyError(cancelled() ? "AbortError" : "NotAllowedError");
                }
                if(!create) selected=prompt.Selected;
            }
            if(cancelled() || vault!=current) return PasskeyError("AbortError");
            if(!VerifyBrowserUser("WinUp: ключ доступа для "+rp) || cancelled() || vault!=current) return PasskeyError("NotAllowedError");
            if(selected!=null && !current.Entries.Contains(selected)) return PasskeyError("not_found");
            var js=new JavaScriptSerializer();
            byte[] client=Encoding.UTF8.GetBytes(js.Serialize(new { type=create ? "webauthn.create" : "webauthn.get",challenge=PasskeyPolicy.Encode(challenge),origin=origin,crossOrigin=false }));
            Dictionary<string,object> response;
            string credentialId;
            if(create) {
                string pem; byte[] cose,spki;
                Keys.Generate(algorithm,out pem,out cose,out spki);
                try {
                    if(cancelled() || vault!=current) return PasskeyError("AbortError");
                    var id=new byte[32]; using(var rng=RandomNumberGenerator.Create()) rng.GetBytes(id);
                    credentialId=PasskeyPolicy.Encode(id);
                    var entry=new LoginEntry { Id=AppStore.NewId(),Name=rp+" — "+userName,Kind="passkey",Target=rp,Login=userName,Args=credentialId,Window=userId,Password=pem };
                    current.Entries.Add(entry);
                    if(!SaveBrowserVault()) { current.Entries.Remove(entry); entry.ClearSecrets(); return PasskeyError("save_failed"); }
                    byte[] auth=Keys.RegisterData(rp,id,cose);
                    response=new Dictionary<string,object> { {"clientDataJSON",PasskeyPolicy.Encode(client)}, {"authenticatorData",PasskeyPolicy.Encode(auth)},
                        {"attestationObject",PasskeyPolicy.Encode(Keys.Attestation(auth))},{"publicKey",PasskeyPolicy.Encode(spki)},{"publicKeyAlgorithm",algorithm},
                        {"clientExtensionResults",PObject(options,"extensions") != null && PObject(options,"extensions").ContainsKey("credProps") ? (object)new { credProps=new { rk=true } } : new Dictionary<string,object>()} };
                } finally { Secure.Wipe(pem); }
            } else {
                if(selected==null) return PasskeyError("not_found");
                credentialId=selected.Args;
                byte[] auth=Keys.AssertionData(rp,selected.PasskeyBackupEligible,selected.PasskeyBackedUp), digest;
                using(var sha=SHA256.Create()) digest=sha.ComputeHash(client);
                byte[] signed=auth.Concat(digest).ToArray();
                if(cancelled() || vault!=current) return PasskeyError("AbortError");
                byte[] signature=selected.UsePassword(pem=>Keys.Sign(pem,signed));
                if(cancelled() || vault!=current) return PasskeyError("AbortError");
                response=new Dictionary<string,object> { {"clientDataJSON",PasskeyPolicy.Encode(client)},{"authenticatorData",PasskeyPolicy.Encode(auth)},
                    {"signature",PasskeyPolicy.Encode(signature)},{"userHandle",selected.Window} };
            }
            return js.Serialize(new { ok=true,publicKey=new { id=credentialId,type="public-key",authenticatorAttachment="platform",response=response } });
        }
    }
    sealed class PasskeyConsentDialog : Dlg,ILockableDialog {
        readonly ComboBox accounts=new ComboBox { DropDownStyle=ComboBoxStyle.DropDownList,Width=380 };
        public bool UseWindows { get; private set; }
        public LoginEntry Selected { get { return accounts.SelectedItem as LoginEntry; } }
        public PasskeyConsentDialog(string origin,string username,List<LoginEntry> entries) : base(username==null ? "Войти ключом доступа" : "Создать ключ доступа") {
            Row("Сайт:",new Label { Text=origin,AutoSize=true,MaximumSize=new System.Drawing.Size(390,100) });
            if(username!=null) Row("Аккаунт:",new Label { Text=username,AutoSize=true,MaximumSize=new System.Drawing.Size(390,100) });
            else { accounts.DisplayMember="Login"; foreach(var entry in entries) accounts.Items.Add(entry); accounts.SelectedIndex=0; Row("Аккаунт:",accounts); }
            Note("WinUp хранит ключ в вашей базе. Для ключа на телефоне, USB-носителе или в Windows выберите «Windows / телефон…».");
            var system=new Button { Text="Windows / телефон…",AutoSize=true };
            system.Click+=(s,e)=> { UseWindows=true; DialogResult=DialogResult.Ignore; Close(); };
            Buttons(system); Ok.Text=username==null ? "Войти" : "Создать";
        }
    }
}
