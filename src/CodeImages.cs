using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Reflection;
using System.Windows.Forms;
namespace WinUp {
    internal static class CodeImages {
        static Assembly library;
        internal static Bitmap Create(string content,string format,int qrVersion=0,string correction="M"){
            if(string.IsNullOrEmpty(content)||content.Length>2000)throw new IOException("Введите текст (до 2000 символов). Для длинного текста используйте заметку.");
            if(format!="QR_CODE"&&format!="CODE_128"&&format!="EAN_13")throw new IOException("Выберите поддерживаемый формат.");
            if(format=="QR_CODE"&&(qrVersion<0||qrVersion>40||Array.IndexOf(new[]{"L","M","Q","H"},correction)<0))throw new IOException("Выберите плотность QR от 1 до 40 или «Авто» и допустимую устойчивость к повреждениям.");
            if(library==null){using(var input=Assembly.GetExecutingAssembly().GetManifestResourceStream("zxing.dll")){if(input==null)throw new IOException("Библиотека создания кодов отсутствует.");using(var bytes=new MemoryStream()){input.CopyTo(bytes);library=Assembly.Load(bytes.ToArray());}}}
            var type=library.GetType("ZXing.BarcodeWriter");var writer=Activator.CreateInstance(type);type.GetProperty("Format").SetValue(writer,Enum.Parse(library.GetType("ZXing.BarcodeFormat"),format),null);
            var options=Activator.CreateInstance(library.GetType("ZXing.Common.EncodingOptions"));foreach(var pair in new[]{new object[]{"Width",format=="QR_CODE"?640:1000},new object[]{"Height",format=="QR_CODE"?640:280},new object[]{"Margin",format=="QR_CODE"?4:12}})options.GetType().GetProperty((string)pair[0]).SetValue(options,pair[1],null);
            if(format=="QR_CODE"){
                var hints=(System.Collections.IDictionary)options.GetType().GetProperty("Hints").GetValue(options,null);
                var hintType=library.GetType("ZXing.EncodeHintType");
                hints[Enum.Parse(hintType,"CHARACTER_SET")]="UTF-8";
                hints[Enum.Parse(hintType,"ERROR_CORRECTION")]=library.GetType("ZXing.QrCode.Internal.ErrorCorrectionLevel").GetField(correction).GetValue(null);
                if(qrVersion>0)hints[Enum.Parse(hintType,"QR_VERSION")]=qrVersion;
            }
            type.GetProperty("Options").SetValue(writer,options,null);
            try{return (Bitmap)type.GetMethod("Write",new[]{typeof(string)}).Invoke(writer,new object[]{content});}
            catch(TargetInvocationException ex){
                if(format=="QR_CODE")throw new IOException(qrVersion>0?"Данные не помещаются в QR выбранной плотности (версия "+qrVersion+"). Выберите «Авто», более высокую плотность или сократите текст.":"Данные не помещаются в QR. Сократите текст или уменьшите устойчивость к повреждениям.",ex.InnerException);
                throw new IOException("Не удалось создать код: "+ex.InnerException.Message);
            }
        }
    }
    sealed class CodeImageDialog:Form,ILockableDialog {
        readonly ComboBox format=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,Dock=DockStyle.Top};readonly ComboBox density=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,Width=285,MaxDropDownItems=12};readonly ComboBox correction=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,Width=235};readonly TextBox content=new TextBox{Multiline=true,Height=100,Dock=DockStyle.Top,MaxLength=2000,ScrollBars=ScrollBars.Vertical};readonly PictureBox preview=new PictureBox{Dock=DockStyle.Fill,SizeMode=PictureBoxSizeMode.Zoom,BackColor=Color.White};readonly Label status=new Label{Dock=DockStyle.Bottom,Height=50};readonly Button save=new Button{Text="Сохранить PNG",AutoSize=true},copy=new Button{Text="Копировать картинку",AutoSize=true};
        internal CodeImageDialog(){Text="WinUp — QR-код и штрихкод";Font=new Font("Segoe UI",10);Icon=AppIcons.Open;Size=new Size(820,780);MinimumSize=new Size(560,570);Padding=new Padding(12);StartPosition=FormStartPosition.CenterParent;format.Items.AddRange(new object[]{"QR-код — текст или ссылка","Code 128 — текст и цифры","EAN-13 — товарный код"});format.SelectedIndex=0;format.AccessibleName="Формат кода";content.AccessibleName="Текст или ссылка для кода";preview.AccessibleName="Предпросмотр кода";var buttons=new FlowLayoutPanel{Dock=DockStyle.Bottom,AutoSize=true};var generate=new Button{Text="Создать код",AutoSize=true};buttons.Controls.AddRange(new Control[]{generate,save,copy});Controls.Add(preview);Controls.Add(content);Controls.Add(format);Controls.Add(status);Controls.Add(buttons);AddQrSettings();generate.Click+=(s,e)=>Generate();save.Click+=(s,e)=>{if(preview.Image==null)return;using(var d=new SaveFileDialog{Filter="Изображение PNG|*.png",FileName="WinUp-code.png",OverwritePrompt=true})if(d.ShowDialog(this)==DialogResult.OK)try{preview.Image.Save(d.FileName,ImageFormat.Png);}catch(Exception ex){status.Text=ex.Message;}};copy.Click+=(s,e)=>{if(preview.Image!=null)try{Clipboard.SetImage(preview.Image);status.Text="Картинка скопирована. Она содержит введённые данные.";}catch(Exception ex){status.Text=ex.Message;}};content.TextChanged+=(s,e)=>ResetImage();format.SelectedIndexChanged+=(s,e)=>ResetImage();ResetImage();FormClosed+=(s,e)=>{ResetImage();content.Clear();};Appearance.Apply(this);preview.BackColor=Color.White;}
        void AddQrSettings(){
            density.AccessibleName="Плотность рисунка QR";correction.AccessibleName="Устойчивость QR к повреждениям";
            density.Items.Add("Авто — минимум для введённых данных");
            for(int version=1;version<=40;version++){int modules=17+4*version;density.Items.Add(version+" · "+modules+" × "+modules+(version==1?" — самый простой":version==40?" — самый плотный":""));}
            density.SelectedIndex=0;
            correction.Items.AddRange(new object[]{"L — низкая","M — средняя","Q — повышенная","H — высокая"});correction.SelectedIndex=1;
            var settings=new FlowLayoutPanel{Dock=DockStyle.Top,AutoSize=true,WrapContents=true,Padding=new Padding(0,4,0,4)};
            foreach(var pair in new[]{new object[]{"Плотность рисунка QR",density},new object[]{"Устойчивость к повреждениям",correction}}){var group=new FlowLayoutPanel{AutoSize=true,FlowDirection=FlowDirection.TopDown,WrapContents=false,Margin=new Padding(0,0,10,0)};group.Controls.Add(new Label{Text=(string)pair[0],AutoSize=true});group.Controls.Add((Control)pair[1]);settings.Controls.Add(group);}
            Controls.Add(settings);Controls.SetChildIndex(settings,Controls.GetChildIndex(format));
            density.SelectedIndexChanged+=(s,e)=>ResetImage();correction.SelectedIndexChanged+=(s,e)=>ResetImage();format.SelectedIndexChanged+=(s,e)=>{density.Enabled=correction.Enabled=format.SelectedIndex==0;};
        }
        void ResetImage(){var old=preview.Image;preview.Image=null;if(old!=null)old.Dispose();save.Enabled=copy.Enabled=false;status.Text="«Авто» выбирает минимальную плотность под данные. Код не шифрует введённый текст.";}
        void Generate(){ResetImage();try{preview.Image=CodeImages.Create(content.Text,new[]{"QR_CODE","CODE_128","EAN_13"}[format.SelectedIndex],density.SelectedIndex,new[]{"L","M","Q","H"}[correction.SelectedIndex]);save.Enabled=copy.Enabled=true;status.Text="Код готов."+(format.SelectedIndex==0&&density.SelectedIndex>0?" QR: "+(17+4*density.SelectedIndex)+" × "+(17+4*density.SelectedIndex)+" элементов.":"")+" Перед использованием проверьте его сканером.";}catch(Exception ex){status.Text=ex.Message;}}
    }
}
