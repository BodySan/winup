using System;
using System.Diagnostics;
using System.IO;

namespace WinUp
{
    static class BrowserPages
    {
        public static string ExtensionUrl(BrowserInfo browser) {
            if(browser==null)return "";
            switch(Path.GetFileName(browser.Exe).ToLowerInvariant()) {
                case "firefox.exe":return "about:debugging#/runtime/this-firefox";
                case "msedge.exe":return "edge://extensions/";
                case "chrome.exe":return "chrome://extensions/";
                case "brave.exe":return "brave://extensions/";
                case "opera.exe":return "opera://extensions/";
                case "vivaldi.exe":return "vivaldi://extensions/";
                case "browser.exe":return browser.Name.IndexOf("yandex",StringComparison.OrdinalIgnoreCase)>=0 || browser.Name.IndexOf("яндекс",StringComparison.OrdinalIgnoreCase)>=0 ? "browser://extensions/" : "";
                default:return "";
            }
        }
        public static bool Firefox(BrowserInfo browser) {return ExtensionUrl(browser).StartsWith("about:",StringComparison.Ordinal);}
        public static ProcessStartInfo ExtensionLaunch(BrowserInfo browser) {
            string address=ExtensionUrl(browser);
            if(address.Length==0 || !File.Exists(browser.Exe))throw new InvalidOperationException("Выбранный браузер не найден или для него не предусмотрена страница расширений. Скопируйте адрес и откройте его вручную.");
            return new ProcessStartInfo(browser.Exe,(Firefox(browser) ? "-new-tab " : "--new-tab ")+"\""+address+"\"") {UseShellExecute=true};
        }
        public static ProcessStartInfo SiteLaunch(string address, BrowserInfo browser) {
            Uri uri;
            if(!Uri.TryCreate(address,UriKind.Absolute,out uri) || uri.Scheme!=Uri.UriSchemeHttps || uri.UserInfo.Length>0)
                throw new InvalidOperationException("Укажите HTTPS-адрес сайта без данных входа в адресе.");
            if(browser==null)return new ProcessStartInfo(uri.AbsoluteUri) {UseShellExecute=true};
            if(!File.Exists(browser.Exe))throw new InvalidOperationException("Выбранный браузер больше не установлен. Выберите другой браузер.");
            return new ProcessStartInfo(browser.Exe,(Path.GetFileName(browser.Exe).Equals("firefox.exe",StringComparison.OrdinalIgnoreCase) ? "-new-tab " : "--new-tab ")+"\""+uri.AbsoluteUri+"\"") {UseShellExecute=true};
        }
    }
}
