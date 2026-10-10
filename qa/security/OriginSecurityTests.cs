using System;
using System.Linq;
using System.Reflection;
using System.Windows.Forms;

namespace WinUp {
    static partial class SecurityHarness {
        static void OriginSecurityRegression() {
            try {OriginSecurityTests();ImportSecurityTests();}
            catch(Exception e){Check("origin-security-unhandled",false,e.ToString());}
            finally{Ui(delegate{form.Close();});}
        }
        static void ImportSecurityTests() {
            string folder=System.IO.Path.Combine(Paths.Root,"synthetic-otp-import");System.IO.Directory.CreateDirectory(folder);
            string uri="otpauth://totp/Учебный:demo?secret=JBSWY3DPEHPK3PXP&issuer=Учебный";
            foreach(var encoding in new System.Text.Encoding[]{new System.Text.UTF8Encoding(true),System.Text.Encoding.Unicode}) {
                string path=System.IO.Path.Combine(folder,encoding.CodePage+".txt");
                System.IO.File.WriteAllText(path,uri,encoding);
                var warnings=new System.Collections.Generic.List<string>();var parsed=OtpImport.Parse(OtpImport.ReadFile(path),warnings);
                Check("otp-import-bom-roundtrip",parsed.Count==1 && parsed[0].Issuer=="Учебный",encoding.WebName+" ordinary export remains readable");
                foreach(var item in parsed)item.ClearSecret();
            }
            string large=System.IO.Path.Combine(folder,"oversized.txt");
            using(var stream=System.IO.File.Create(large)){stream.SetLength(OtpImport.MaxInput+1L);}
            bool rejected=false;try{OtpImport.ReadFile(large);}catch(System.IO.InvalidDataException){rejected=true;}
            Check("otp-import-oversized-file-rejected",rejected,"file is rejected before allocating its declared length");
            var notes=new System.Collections.Generic.List<string>();
            Check("otp-import-oversized-text-rejected",OtpImport.Parse(new string('x',OtpImport.MaxInput+1),notes).Count==0 && notes.Count>0,"pasted export is rejected before regex and JSON processing");
            var deepNotes=new System.Collections.Generic.List<string>();
            string nested=new string('[',80)+"0"+new string(']',80);
            Check("otp-import-deep-json-rejected",OtpImport.Parse(nested,deepNotes).Count==0 && deepNotes.Count>0,"nested input produces a readable refusal");
        }
        static void OriginSecurityTests() {
            Ui(delegate{Lock();NewVault(false);});
            string same=Fill("https://example.com/login",false,"origin-positive-"+Guid.NewGuid());
            Check("origin-original-site-can-fill",same.Contains("Audit-only-secret!"),"positive control: ordinary HTTPS account works");
            System.Windows.Forms.Timer cancel=null;
            Ui(delegate {
                cancel=new System.Windows.Forms.Timer {Interval=30};
                cancel.Tick+=(s,e)=>{foreach(var prompt in Application.OpenForms.Cast<Form>().OfType<ConfirmFillDialog>().ToArray())prompt.Close();};
                cancel.Start();
            });
            try {
                foreach(string url in new[]{"https://example.com:8443/login","https://example.com:444/login"}) {
                    string reply=Fill(url,false,"origin-port-"+Guid.NewGuid());
                    Check("origin-different-port-needs-consent",!reply.Contains("Audit-only-secret!") && !(bool)Parse(reply)["ok"],url+"; cancelled prompts never disclose the password");
                }
                string alias=Fill("https://www.example.com/login",false,"origin-www-"+Guid.NewGuid());
                Check("origin-www-service-needs-consent",!alias.Contains("Audit-only-secret!") && !(bool)Parse(alias)["ok"],"a sibling service does not inherit credentials without reviewed authorization");
                Ui(delegate{form.VaultNow.Entries[0].Target="http://example.com:8080/";});
                string changed=Fill("https://example.com:8080/login",false,"origin-scheme-"+Guid.NewGuid());
                Check("origin-different-scheme-needs-consent",!changed.Contains("Audit-only-secret!") && !(bool)Parse(changed)["ok"],"HTTP and HTTPS services on the same host/port have separate trust");
                Ui(delegate{
                    NewVault(false);
                    var current=form.VaultNow;
                    Check("origin-save-same-account-matches",MainForm.BrowserSaveMatches(current,"https://example.com/login","audit-user").Count==1,"positive control");
                    Check("origin-save-other-port-cannot-update-account",MainForm.BrowserSaveMatches(current,"https://example.com:8443/login","audit-user").Count==0,"separate origin cannot select original account for update");
                    string token="origin-list-"+Guid.NewGuid();BrowserPair.Save(token,"Synthetic origin review");
                    string json=(string)typeof(BrowserServer).GetMethod("ListOrSearch",Private).Invoke(server,new object[]{token,"https://example.com:8443/login",null});
                    var items=(System.Collections.ArrayList)Parse(json)["items"];
                    var first=(System.Collections.Generic.Dictionary<string,object>)items[0];
                    Check("origin-list-other-port-not-exact",!(bool)first["exact"],"the account picker must show that confirmation is required");
                    BrowserPair.Forget(BrowserPair.HashToken(token));
                    Check("origin-default-port-compatible",SiteDomain.SameOrigin("https://example.com:443/","https://example.com/login"),"the same service retains its effective port");
                    Check("origin-idn-and-root-dot-compatible",SiteDomain.SameOrigin("https://пример.рф./","https://xn--e1afmkfd.xn--p1ai/login"),"DNS normalization preserves the same service");
                    Check("origin-reviewed-sso-preserved",LoginProfiles.MatchesLoginOrigin(new LoginEntry {Target="https://www.youtube.com",Name="YouTube"},"https://accounts.google.com/signin"),"explicit reviewed identity-provider origin remains usable");
                    string consentId="synthetic-origin-"+Guid.NewGuid();
                    BrowserAllow.Add(consentId,"https://login.example.com:8443","Synthetic origin review");
                    Check("origin-remember-exact-service",BrowserAllow.Has(consentId,"https://login.example.com:8443"),"positive control for remembered approval");
                    Check("origin-remember-no-other-port",!BrowserAllow.Has(consentId,"https://login.example.com:444")&&!BrowserAllow.Has(consentId,"https://login.example.com"),"approval never grants a different service");
                    Check("origin-remember-no-other-scheme",!BrowserAllow.Has(consentId,"http://login.example.com:8443"),"approval never grants HTTP");
                    Check("origin-host-only-approval-not-trusted",!BrowserAllow.Has(consentId,"login.example.com"),"old hostname-only approvals cannot authorize a full origin");
                });
                string approved="https://login.example.com:8443";
                try {
                    BrowserAllow.Add("audit-entry",approved,"Synthetic origin review");
                    string accepted=Fill(approved+"/login",false,"origin-approved-"+Guid.NewGuid());
                    Check("origin-approved-service-can-fill",accepted.Contains("Audit-only-secret!"),"a full-origin approval permits the intended service");
                    string other=Fill("https://login.example.com:444/login",false,"origin-unapproved-"+Guid.NewGuid());
                    Check("origin-approved-service-does-not-grant-sibling-port",!other.Contains("Audit-only-secret!") && !(bool)Parse(other)["ok"],"actual password delivery remains limited to the approved port");
                } finally {
                    using(var key=Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\WinUp\Browser\Allowed",true))
                        if(key!=null)key.DeleteValue(BrowserPair.HashToken("audit-entry|"+approved),false);
                }
                Ui(delegate{form.VaultNow.Entries[0].Target="https://www.youtube.com";form.VaultNow.Entries[0].Name="YouTube";});
                string sso=Fill("https://accounts.google.com/signin",false,"origin-sso-"+Guid.NewGuid());
                Check("origin-reviewed-sso-can-fill",sso.Contains("Audit-only-secret!"),"the actual fill route preserves reviewed Google login for YouTube");
            } finally{Ui(delegate{cancel.Stop();cancel.Dispose();Lock();});}
        }
    }
}
