// Field mappings follow KeePass 2.61.1 BitwardenJson112/LastPassCsv2/OnePw1Pux8
// and the public export schemas. WinUp keeps its own preview and duplicate policy.
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace WinUp {
    internal sealed class ImportSeed {
        internal string Name="",Url="",Login="",Password="",Notes="",Otp="",Category="",Warning="";internal bool Pinned;
        internal readonly Dictionary<string,string> Fields=new Dictionary<string,string>();
    }
    internal static partial class PasswordImport {
        static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=8*1024*1024,RecursionLimit=64};
        static string S(object value){return value as string??(value==null?"":Convert.ToString(value,System.Globalization.CultureInfo.InvariantCulture));}
        static object Get(object value,string name){var map=value as Dictionary<string,object>;return map!=null&&map.ContainsKey(name)?map[name]:null;}
        static string Text(object value,string name){return S(Get(value,name));}
        static bool WebAddress(string value){Uri uri;return Uri.TryCreate(value,UriKind.Absolute,out uri)&&(uri.Scheme=="https"||uri.Scheme=="http")&&uri.UserInfo.Length==0;}
        static void Addresses(ImportSeed seed,IEnumerable<string> source){var all=source.Where(s=>!string.IsNullOrWhiteSpace(s)).Distinct().ToList();seed.Url=all.FirstOrDefault(WebAddress)??all.FirstOrDefault()??"";foreach(var value in all)if(value!=seed.Url)Field(seed,"Дополнительный адрес",value);}
        static IEnumerable<object> Items(object value){return value as object[]??(value is ArrayList?((ArrayList)value).Cast<object>():Enumerable.Empty<object>());}
        static void Field(ImportSeed seed,string name,string value){
            if(string.IsNullOrEmpty(value))return;if(seed.Fields.Count>=128)throw new IOException("В записи слишком много дополнительных полей.");
            name=string.IsNullOrWhiteSpace(name)?"Поле":name.Trim();if(name.Length>110)name=name.Substring(0,110);if(!KdbxStore.IsUserField(name))name="Импорт · "+name;
            string unique=name;for(int n=2;seed.Fields.ContainsKey(unique);n++)unique=name+" ("+n+")";KdbxStore.ValidateFieldName(unique);seed.Fields.Add(unique,value);
        }
        internal static void ReadImportedFields(LoginEntry entry,string json){
            var map=Json.Deserialize<Dictionary<string,string>>(json);if(map==null||map.Count>128)throw new IOException("Неверный список дополнительных полей.");
            foreach(var item in map){KdbxStore.ValidateFieldName(item.Key);if(item.Value!=null&&item.Value.Length>65536)throw new IOException("Дополнительное поле слишком большое.");entry.CustomFields.Add(new AccountSecretField{Name=Copy(item.Key),Value=item.Value??""});Secure.Wipe(item.Value);}
        }
        internal static PasswordImportResult ReadAdvanced(string path,IEnumerable<LoginEntry> existing,IEnumerable<OtpEntry> codes,Form owner,bool generic=false){
            using(var lease=SourceLease.Acquire(path,false)){
                string text=null;byte[] bytes=null;
                try{
                    if(Path.GetExtension(path).Equals(".1pux",StringComparison.OrdinalIgnoreCase)){
                        using(var input=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read))using(var archive=new ZipArchive(input,ZipArchiveMode.Read)){
                            var entries=archive.Entries.Where(e=>e.FullName=="export.data").ToList();if(entries.Count!=1||entries[0].Length>8*1024*1024)throw new IOException("В 1PUX нужен один export.data размером до 8 МиБ.");
                            using(var stream=entries[0].Open())using(var output=new MemoryStream()){byte[] buffer=new byte[8192];try{int n;while((n=stream.Read(buffer,0,buffer.Length))>0){if(output.Length+n>8*1024*1024)throw new IOException("Данные 1PUX слишком большие.");output.Write(buffer,0,n);}bytes=output.ToArray();}finally{Array.Clear(buffer,0,buffer.Length);}}
                        }
                        text=new UTF8Encoding(false,true).GetString(bytes);return ParseJsonExport(text,existing,codes);
                    }
                    bytes=SafeStorage.ReadBounded(path,8*1024*1024);
                    if(bytes.Length>=2&&bytes[0]==255&&bytes[1]==254)text=new UnicodeEncoding(false,true,true).GetString(bytes,2,bytes.Length-2);
                    else if(bytes.Length>=2&&bytes[0]==254&&bytes[1]==255)text=new UnicodeEncoding(true,true,true).GetString(bytes,2,bytes.Length-2);
                    else text=new UTF8Encoding(false,true).GetString(bytes).TrimStart('\uFEFF');
                    if(Path.GetExtension(path).Equals(".json",StringComparison.OrdinalIgnoreCase))return ParseJsonExport(text,existing,codes);
                    return ReadCsvExport(text,existing,codes,owner,generic);
                }finally{if(bytes!=null)Array.Clear(bytes,0,bytes.Length);Secure.Wipe(text);}
            }
        }
        internal static PasswordImportResult ParseJsonExport(string text,IEnumerable<LoginEntry> existing,IEnumerable<OtpEntry> codes=null){
            object root=Json.DeserializeObject(text);var seeds=new List<ImportSeed>();var skipped=new List<string>();string format;
            try{
                if(Get(root,"accounts")!=null){format="1Password 1PUX";foreach(var account in Items(Get(root,"accounts")))foreach(var vault in Items(Get(account,"vaults")))foreach(var item in Items(Get(vault,"items"))){
                    object overview=Get(item,"overview"),details=Get(item,"details");var seed=new ImportSeed{Name=Text(overview,"title"),Password=Text(details,"password"),Notes=Text(details,"notesPlain"),Category=Text(Get(vault,"attrs"),"name"),Pinned=Convert.ToInt64(Get(item,"favIndex")??0)>0};
                    foreach(var field in Items(Get(details,"loginFields"))){string designation=Text(field,"designation");if(designation=="username")seed.Login=Text(field,"value");else if(designation=="password")seed.Password=Text(field,"value");else Field(seed,Text(field,"name"),Text(field,"value"));}
                    foreach(var section in Items(Get(details,"sections")))foreach(var field in Items(Get(section,"fields"))){var value=Get(field,"value") as Dictionary<string,object>;if(value==null)continue;foreach(var pair in value){if(pair.Key=="totp")seed.Otp=S(pair.Value);else Field(seed,Text(field,"title"),pair.Value is string?S(pair.Value):Json.Serialize(pair.Value));}}
                    Addresses(seed,new[]{Text(overview,"url")}.Concat(Items(Get(overview,"urls")).Select(url=>Text(url,"url"))));
                    if(Text(item,"state")=="archived")seed.Warning="Архивная запись — выберите явно";
                    if(Get(details,"documentAttributes")!=null||Items(Get(details,"passwordHistory")).Any())seed.Warning+=(seed.Warning.Length>0?"; ":"")+"Вложения / история исходного менеджера не перенесены";
                    AddSeed(seeds,skipped,seed);
                }}else if(Get(root,"items")!=null){
                    if(Get(root,"encrypted") is bool&&(bool)Get(root,"encrypted"))throw new IOException("Это зашифрованный экспорт Bitwarden. Выберите в Bitwarden обычный JSON или CSV для переноса.");
                    format="Bitwarden JSON";var folders=Items(Get(root,"folders")).ToDictionary(f=>Text(f,"id"),f=>Text(f,"name"));
                    foreach(var item in Items(Get(root,"items"))){var login=Get(item,"login");string category;folders.TryGetValue(Text(item,"folderId"),out category);var seed=new ImportSeed{Name=Text(item,"name"),Login=Text(login,"username"),Password=Text(login,"password"),Otp=Text(login,"totp"),Notes=Text(item,"notes"),Category=category??"",Pinned=Get(item,"favorite") is bool&&(bool)Get(item,"favorite")};
                        Addresses(seed,Items(Get(login,"uris")).Select(uri=>Text(uri,"uri")));
                        foreach(var field in Items(Get(item,"fields"))){if(Convert.ToInt32(Get(field,"type")??0)==3){seed.Warning="Ссылочное поле исходного менеджера не перенесено";continue;}Field(seed,Text(field,"name"),Text(field,"value"));}
                        if(Items(Get(login,"fido2Credentials")).Any())seed.Warning="Ключи доступа из JSON не перенесены — пароль можно выбрать отдельно";
                        if(Convert.ToInt32(Get(item,"type")??0)!=1)skipped.Add(seed.Name+": тип записи не является паролем сайта");else AddSeed(seeds,skipped,seed);
                    }
                }else throw new IOException("Неизвестный JSON. Поддерживается незашифрованный экспорт Bitwarden и данные 1Password 1PUX.");
                var result=FromSeeds(seeds,existing,codes);result.Format=format;foreach(var message in skipped)result.Rows.Add(new PasswordImportRow{Selectable=false,DefaultSelected=false,Status=message});return result;
            }finally{WipeJson(root);foreach(var seed in seeds){Secure.Wipe(seed.Password);Secure.Wipe(seed.Otp);foreach(var value in seed.Fields.Values)Secure.Wipe(value);}}
        }
        static void AddSeed(List<ImportSeed> seeds,List<string> skipped,ImportSeed seed){if(seeds.Count+skipped.Count>=10000)throw new IOException("За один импорт — до 10 000 записей.");if(seed.Password.Length==0){skipped.Add(seed.Name+": нет обычного пароля; вложения, заметки и passkey отдельно не импортируются");return;}seeds.Add(seed);}
        static void WipeJson(object value){if(value is string)Secure.Wipe((string)value);else if(value is Dictionary<string,object>)foreach(var item in ((Dictionary<string,object>)value).Values)WipeJson(item);else foreach(var item in Items(value))WipeJson(item);}
        internal static PasswordImportResult FromSeeds(IEnumerable<ImportSeed> seeds,IEnumerable<LoginEntry> existing,IEnumerable<OtpEntry> codes=null){
            var csv=new StringBuilder("name,url,username,password,notes,otpauth,category,pinned,custom_fields,import_warning\n");int count=0;string canonical=null;
            try{foreach(var seed in seeds){if(++count>10000)throw new IOException("Слишком много записей.");string otp=seed.Otp;if(otp.Length>0&&!otp.StartsWith("otpauth://",StringComparison.OrdinalIgnoreCase))otp="otpauth://totp/"+Uri.EscapeDataString(seed.Name+":"+seed.Login)+"?secret="+Uri.EscapeDataString(otp)+"&issuer="+Uri.EscapeDataString(seed.Name);
                    foreach(var value in new[]{seed.Name,seed.Url,seed.Login,seed.Password,seed.Notes,otp,seed.Category,seed.Pinned?"1":"0",Json.Serialize(seed.Fields),seed.Warning})csv.Append('"').Append((value??"").Replace("\"","\"\"")).Append("\",");csv.Length--;csv.Append('\n');}
                canonical=csv.ToString();return Parse(canonical,existing,codes);
            }finally{Secure.Wipe(canonical);for(int i=0;i<csv.Length;i++)csv[i]='\0';csv.Clear();}
        }
        static readonly string[][] CsvNames={new[]{"url","website","website_url","login_uri","адрес","сайт"},new[]{"username","login_username","login","user","логин"},new[]{"password","login_password","пароль"},new[]{"title","name","название"},new[]{"notes","note","extra","заметки"},new[]{"otpauth","login_totp","otp","totp","one-time password"},new[]{"category","folder","grouping","категория"},new[]{"pinned","favorite","fav"}};
        internal static PasswordImportResult ReadCsvExport(string text,IEnumerable<LoginEntry> existing,IEnumerable<OtpEntry> codes,Form owner,bool generic=false){
            char delimiter=',';var rows=Csv(text,delimiter);if(rows.Count==0)throw new IOException("CSV пуст.");var indices=CsvNames.Select(names=>Array.FindIndex(rows[0],column=>names.Contains(column.Trim().TrimStart('\uFEFF'),StringComparer.OrdinalIgnoreCase))).ToArray();
            bool extras=true,header=true;
            try{if(generic||indices.Take(3).Any(i=>i<0))using(var dialog=new CsvMappingDialog(text)){generic=true;if(dialog.ShowDialog(owner)!=DialogResult.OK)return null;foreach(var row in rows)Clear(row);rows=Csv(text,dialog.Delimiter);indices=dialog.Indices;delimiter=dialog.Delimiter;extras=dialog.ExtraFields;header=dialog.Header;}
                if(!generic&&rows[0].Select(v=>v.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).Count()!=rows[0].Length)throw new IOException("В CSV повторяется название столбца. Выберите произвольный CSV и назначьте столбцы вручную.");
                return ParseMappedCsv(rows,existing,codes,indices,extras,header,generic?"CSV с выбранными столбцами":rows[0].Contains("login_uri")?"Bitwarden CSV":rows[0].Contains("grouping")?"LastPass CSV":rows[0].Contains("title")||rows[0].Contains("Title")?"Apple / 1Password CSV":"Google / CSV");
            }finally{foreach(var row in rows)Clear(row);}
        }
        internal static PasswordImportResult ParseMappedCsv(List<string[]> rows,IEnumerable<LoginEntry> existing,IEnumerable<OtpEntry> codes,int[] indices,bool extras,bool header,string format){
            var seeds=new List<ImportSeed>();try{
                for(int n=header?1:0;n<rows.Count;n++){var row=rows[n];if(row.Length!=rows[0].Length)throw new IOException("Строка "+(n+1)+": число столбцов отличается от выбранной схемы.");Func<int,string> value=field=>indices[field]>=0?row[indices[field]]:"";var seed=new ImportSeed{Name=value(3),Url=value(0),Login=value(1),Password=value(2),Notes=value(4),Otp=value(5),Category=value(6),Pinned=value(7)=="1"||value(7).Equals("true",StringComparison.OrdinalIgnoreCase)};
                    bool unsupported=false;if(extras)for(int i=0;i<row.Length;i++)if(!indices.Contains(i)){
                        string name=header?rows[0][i].Trim():"Столбец "+(i+1);
                        if(name=="custom_fields"&&!string.IsNullOrEmpty(row[i])){
                            var fields=Json.Deserialize<Dictionary<string,string>>(row[i]);if(fields==null||fields.Count>128)throw new IOException("Неверный список дополнительных полей.");foreach(var field in fields)Field(seed,field.Key,field.Value);
                        }else if(name=="import_warning")seed.Warning=row[i];
                        else if(name=="type"&&format=="Bitwarden CSV"){unsupported=row[i]!="login";if(unsupported)seed.Warning="Неподдерживаемый тип Bitwarden: "+row[i];}
                        else if(name=="reprompt"&&format=="Bitwarden CSV")continue;
                        else if(name=="fields"&&format=="Bitwarden CSV"){
                            foreach(var line in row[i].Split(new[]{'\n'},StringSplitOptions.RemoveEmptyEntries)){int colon=line.IndexOf(": ",StringComparison.Ordinal);if(colon>0)Field(seed,line.Substring(0,colon),line.Substring(colon+2).TrimEnd('\r'));else Field(seed,"Поле из Bitwarden",line.TrimEnd('\r'));}
                        }else Field(seed,name,row[i]);
                    }
                    if(unsupported)seed.Password="";seeds.Add(seed);
                }
                var result=FromSeeds(seeds,existing,codes);result.Format=format;return result;
            }finally{foreach(var seed in seeds)foreach(var field in seed.Fields.Values)Secure.Wipe(field);}
        }
    }
    sealed class CsvMappingDialog:Dlg,ILockableDialog {
        readonly string text;readonly ComboBox delimiter=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,Width=250};readonly CheckBox header=new CheckBox{Text="Первая строка содержит названия столбцов",Checked=true,AutoSize=true},extras=new CheckBox{Text="Остальные столбцы сохранить как защищённые поля",Checked=true,AutoSize=true};readonly ComboBox[] fields=Enumerable.Range(0,8).Select(i=>new ComboBox{Width=300,DropDownStyle=ComboBoxStyle.DropDownList}).ToArray();
        internal char Delimiter{get{return delimiter.SelectedIndex==1?';':delimiter.SelectedIndex==2?'\t':',';}}internal bool Header{get{return header.Checked;}}internal bool ExtraFields{get{return extras.Checked;}}internal int[] Indices{get{return fields.Select(f=>f.SelectedIndex-1).ToArray();}}
        internal CsvMappingDialog(string text):base("Выбрать столбцы CSV"){
            this.text=text;Note("Укажите столбцы адреса, логина и пароля. Если названий столбцов нет, снимите галочку первой строки: вместо её данных появятся номера. Затем откроется просмотр записей и дублей.");delimiter.Items.AddRange(new object[]{"Запятая ,","Точка с запятой ;","Табуляция"});Row("Разделитель:",delimiter);FullRow(header);
            string[] titles={"Адрес сайта","Логин","Пароль","Название","Заметки","2FA: ключ / OTPAuth","Категория","Закрепление: 1 / true"};for(int i=0;i<fields.Length;i++)Row(titles[i]+":",fields[i]);FullRow(extras);Buttons();delimiter.SelectedIndex=0;delimiter.SelectedIndexChanged+=(s,e)=>FillColumns();header.CheckedChanged+=(s,e)=>FillColumns();FillColumns();
            Ok.Click+=(s,e)=>{if(Indices.Take(3).Any(i=>i<0))Fail("Выберите адрес, логин и пароль.");else if(Indices.Where(i=>i>=0).Distinct().Count()!=Indices.Count(i=>i>=0))Fail("Один столбец нельзя назначать нескольким полям.");};
        }
        void FillColumns(){List<string[]> rows=null;try{rows=PasswordImport.Csv(text,Delimiter);if(rows.Count==0)throw new IOException("CSV пуст.");foreach(var field in fields){field.Items.Clear();field.Items.Add("Не переносить");for(int i=0;i<rows[0].Length;i++)field.Items.Add(header.Checked?(i+1)+" · "+new string(rows[0][i].ToCharArray()):"Столбец "+(i+1));field.SelectedIndex=0;}}catch(Exception ex){MessageBox.Show(this,ex.Message,Text);}finally{if(rows!=null)foreach(var row in rows)foreach(var value in row)Secure.Wipe(value);}}
    }
}
