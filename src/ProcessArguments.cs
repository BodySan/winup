using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace WinUp {
    internal static class ProcessArguments {
        // Parse the Windows argument syntax, then quote individual values. This
        // is not a shell parser: commands are never accepted as batch arguments.
        internal static string[] Parse(string value) {
            if(value==null)return new string[0];
            if(value.Length>32700||value.Any(c=>char.IsControl(c)&&c!='\t'))throw new IOException("Недопустимые параметры запуска.");
            var result=new List<string>();int i=0;
            while(i<value.Length){
                while(i<value.Length&&char.IsWhiteSpace(value[i]))i++;
                if(i==value.Length)break;
                var token=new StringBuilder();bool quoted=false;
                while(i<value.Length&&(quoted||!char.IsWhiteSpace(value[i]))){
                    int slashes=0;while(i<value.Length&&value[i]=='\\'){slashes++;i++;}
                    if(i<value.Length&&value[i]=='"'){
                        token.Append('\\',slashes/2);
                        if(slashes%2!=0)token.Append('"');else quoted=!quoted;
                        i++;
                    }else{token.Append('\\',slashes);if(i<value.Length&&(quoted||!char.IsWhiteSpace(value[i])))token.Append(value[i++]);}
                }
                if(quoted)throw new IOException("В параметрах запуска не закрыта кавычка.");
                result.Add(token.ToString());
            }
            return result.ToArray();
        }
        internal static string Quote(string value){
            if(value==null||value.Any(char.IsControl))throw new IOException("Недопустимый параметр запуска.");
            var result=new StringBuilder("\"");int slashes=0;
            foreach(char c in value){if(c=='\\'){slashes++;continue;}if(c=='"'){result.Append('\\',slashes*2+1);result.Append(c);}else{result.Append('\\',slashes);result.Append(c);}slashes=0;}
            result.Append('\\',slashes*2);return result.Append('"').ToString();
        }
        internal static string Join(string[] values){return string.Join(" ",values.Select(Quote));}
        internal static ProcessStartInfo Script(string path,string arguments,bool keepOpen=true){
            string[] values=Parse(arguments);
            if(path.EndsWith(".ps1",StringComparison.OrdinalIgnoreCase))
                return new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),@"WindowsPowerShell\v1.0\powershell.exe"),"-NoProfile -ExecutionPolicy Bypass "+(keepOpen?"-NoExit ":"")+"-File "+Quote(path)+" "+Join(values));
            // cmd expands even quoted %, !, and control operators. Restrict both
            // the script path and each value before constructing its command.
            if(path.Any(c=>char.IsControl(c)||"\"%!".IndexOf(c)>=0))throw new IOException("Путь сценария содержит подстановку командной строки.");
            foreach(string value in values)
                if(value.Any(c=>char.IsControl(c)||"\"&|<>^%!()".IndexOf(c)>=0))
                    throw new IOException("Параметры .cmd/.bat содержат управляющие символы командной строки. Поместите команды в сам сценарий, а здесь укажите только значения параметров.");
            return new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"cmd.exe"),"/d /s "+(keepOpen?"/k":"/c")+" \""+Quote(path)+" "+Join(values)+"\"");
        }
    }
}
