using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

static class GuideCheck {
    static string root=AppDomain.CurrentDomain.BaseDirectory;
    static JavaScriptSerializer json=new JavaScriptSerializer();
    static List<object> checks=new List<object>();
    [STAThread] static void Main() {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        var form=new Form { Text="WinUp — проверка инструкции", ClientSize=new Size(1280,900), ShowInTaskbar=false };
        form.Shown+=async(s,e)=>{
            try { await Run(form); }
            catch(Exception ex) { checks.Add(new {name="Unexpected error",passed=false,error=ex.ToString()}); }
            finally { File.WriteAllText(Path.Combine(root,"guide-check.json"),json.Serialize(checks)); form.Close(); }
        };
        Application.Run(form);
    }
    static void Check(string name,bool passed) {
        checks.Add(new {name=name,passed=passed});
        File.WriteAllText(Path.Combine(root,"guide-check.json"),json.Serialize(checks));
        if(!passed)throw new Exception(name);
    }
    static async Task<bool> Bool(WebView2 web,string script) { return (await web.CoreWebView2.ExecuteScriptAsync(script))=="true"; }
    static async Task Snapshot(WebView2 web,string name) {
        await Task.Delay(180);
        using(var stream=File.Create(Path.Combine(root,name+".png")))await web.CoreWebView2.CapturePreviewAsync(CoreWebView2CapturePreviewImageFormat.Png,stream);
    }
    static async Task Run(Form form) {
        var web=new WebView2 { Dock=DockStyle.Fill };form.Controls.Add(web);
        var env=await CoreWebView2Environment.CreateAsync(null,Path.Combine(root,"guide-profile"));
        await web.EnsureCoreWebView2Async(env);
        web.CoreWebView2.NavigationStarting+=(s,e)=>{if(!e.Uri.StartsWith("file:///C:/WinUp/",StringComparison.OrdinalIgnoreCase))e.Cancel=true;};
        await web.CoreWebView2.AddScriptToExecuteOnDocumentCreatedAsync("window.__docErrors=[];addEventListener('error',e=>__docErrors.push(e.message));addEventListener('unhandledrejection',e=>__docErrors.push(String(e.reason)));");
        var loaded=new TaskCompletionSource<bool>();web.CoreWebView2.NavigationCompleted+=(s,e)=>loaded.TrySetResult(e.IsSuccess);
        web.CoreWebView2.Navigate(new Uri("C:\\WinUp\\Инструкция.html").AbsoluteUri);
        Check("Guide opens from its final location",await loaded.Task);
        await web.CoreWebView2.ExecuteScriptAsync("document.querySelectorAll('figure img').forEach(i=>i.loading='eager')");
        for(int n=0;n<100;n++){if(await Bool(web,"[...document.querySelectorAll('figure img')].every(i=>i.complete&&i.naturalWidth>0)"))break;await Task.Delay(100);}
        Check("All 37 embedded screenshots load offline",await Bool(web,"document.querySelectorAll('figure img').length===37&&[...document.querySelectorAll('figure img')].every(i=>i.complete&&i.naturalWidth>0)"));
        Check("Contents links lead to existing chapters",await Bool(web,"[...document.querySelectorAll('a[href^=\"#\"]')].every(a=>document.getElementById(a.hash.slice(1)))"));
        Check("Each figure has a descriptive caption",await Bool(web,"[...document.querySelectorAll('figure')].every(f=>f.querySelector('img').alt&&f.querySelector('figcaption').textContent)"));
        await web.CoreWebView2.ExecuteScriptAsync("var q=document.getElementById('toc-filter');q.value='2FA';q.dispatchEvent(new Event('input'))");
        Check("Contents search filters matching sections",await Bool(web,"[...document.querySelectorAll('nav li')].some(i=>i.hidden)&&[...document.querySelectorAll('nav li')].filter(i=>!i.hidden).every(i=>i.textContent.toLowerCase().includes('2fa'))"));
        await web.CoreWebView2.ExecuteScriptAsync("q.value='';q.dispatchEvent(new Event('input'))");
        Check("Clearing contents search restores sections",await Bool(web,"[...document.querySelectorAll('nav li')].every(i=>!i.hidden)"));
        foreach(var size in new[]{new Size(1280,900),new Size(640,900),new Size(390,844)}) {
            form.ClientSize=size;await Task.Delay(150);
            Check("Document fits width "+size.Width,await Bool(web,"document.documentElement.scrollWidth<=innerWidth+1"));
        }
        form.ClientSize=new Size(1280,900);await Task.Delay(150);
        await web.CoreWebView2.CallDevToolsProtocolMethodAsync("Emulation.setEmulatedMedia","{\"features\":[{\"name\":\"prefers-color-scheme\",\"value\":\"light\"}]}");
        await web.CoreWebView2.ExecuteScriptAsync("scrollTo(0,0)");await Snapshot(web,"guide-contents-light");
        await web.CoreWebView2.ExecuteScriptAsync("document.querySelector('figure').scrollIntoView();window.__beforeZoom=scrollY;document.querySelector('.figure-open').click()");
        Check("Screenshot opens in a modal at original size",await Bool(web,"document.getElementById('image-viewer').open&&document.getElementById('large-image').src===document.querySelector('figure img').src"));
        await Snapshot(web,"guide-zoom");
        await web.CoreWebView2.ExecuteScriptAsync("document.getElementById('close-image').click()");
        Check("Closing screenshot returns to same text position",await Bool(web,"!document.getElementById('image-viewer').open&&Math.abs(scrollY-window.__beforeZoom)<2"));
        await Task.Delay(100);
        Check("Closing screenshot releases large image",await Bool(web,"!document.getElementById('large-image').hasAttribute('src')"));
        await Snapshot(web,"guide-main-light");
        await web.CoreWebView2.CallDevToolsProtocolMethodAsync("Emulation.setEmulatedMedia","{\"features\":[{\"name\":\"prefers-color-scheme\",\"value\":\"dark\"}]}");
        await Snapshot(web,"guide-main-dark");
        await web.CoreWebView2.ExecuteScriptAsync("document.querySelectorAll('figure')[6].scrollIntoView()");await Snapshot(web,"guide-entry");
        form.ClientSize=new Size(390,844);await Task.Delay(150);
        await web.CoreWebView2.ExecuteScriptAsync("document.getElementById('browser').scrollIntoView()");await Snapshot(web,"guide-narrow");
        Check("No document script errors",await Bool(web,"window.__docErrors.length===0"));
        web.Dispose();
    }
}
