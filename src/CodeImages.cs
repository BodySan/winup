using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Reflection;
using System.Windows.Forms;
namespace WinUp {
    internal static class CodeImages {
        static Assembly library;
        internal static Bitmap Create(string content,string format){
            if(string.IsNullOrEmpty(content)||content.Length>2000)throw new IOException("Введите текст (до 2000 символов). Для длинного текста используйте заметку.");
            if(format!="QR_CODE"&&format!="CODE_128"&&format!="EAN_13")throw new IOException("Выберите поддерживаемый формат.");
            if(library==null){using(var input=Assembly.GetExecutingAssembly().GetManifestResourceStream("zxing.dll")){if(input==null)throw new IOException("Библиотека создания кодов отсутствует.");using(var bytes=new MemoryStream()){input.CopyTo(bytes);library=Assembly.Load(bytes.ToArray());}}}
            var type=library.GetType("ZXing.BarcodeWriter");var writer=Activator.CreateInstance(type);type.GetProperty("Format").SetValue(writer,Enum.Parse(library.GetType("ZXing.BarcodeFormat"),format),null);
            var options=Activator.CreateInstance(library.GetType("ZXing.Common.EncodingOptions"));foreach(var pair in new[]{new object[]{"Width",format=="QR_CODE"?640:1000},new object[]{"Height",format=="QR_CODE"?640:280},new object[]{"Margin",format=="QR_CODE"?4:12}})options.GetType().GetProperty((string)pair[0]).SetValue(options,pair[1],null);
            if(format=="QR_CODE"){var hints=(System.Collections.IDictionary)options.GetType().GetProperty("Hints").GetValue(options,null);hints[Enum.Parse(library.GetType("ZXing.EncodeHintType"),"CHARACTER_SET")]="UTF-8";}
            type.GetProperty("Options").SetValue(writer,options,null);
            try{return (Bitmap)type.GetMethod("Write",new[]{typeof(string)}).Invoke(writer,new object[]{content});}catch(TargetInvocationException ex){throw new IOException("Не удалось создать код: "+ex.InnerException.Message);}
        }
    }
    sealed class CodeImageDialog:Form,ILockableDialog {
        readonly ComboBox format=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,Dock=DockStyle.Top};readonly TextBox content=new TextBox{Multiline=true,Height=100,Dock=DockStyle.Top,MaxLength=2000,ScrollBars=ScrollBars.Vertical};readonly PictureBox preview=new PictureBox{Dock=DockStyle.Fill,SizeMode=PictureBoxSizeMode.Zoom,BackColor=Color.White};readonly Label status=new Label{Dock=DockStyle.Bottom,Height=44};readonly Button save=new Button{Text="Сохранить PNG",AutoSize=true},copy=new Button{Text="Копировать картинку",AutoSize=true};
        internal CodeImageDialog(){Text="WinUp — QR-код и штрихкод";Font=new Font("Segoe UI",10);Icon=AppIcons.Open;Size=new Size(760,690);MinimumSize=new Size(530,480);Padding=new Padding(12);StartPosition=FormStartPosition.CenterParent;format.Items.AddRange(new object[]{"QR-код — текст или ссылка","Code 128 — текст и цифры","EAN-13 — товарный код"});format.SelectedIndex=0;format.AccessibleName="Формат кода";content.AccessibleName="Текст или ссылка для кода";preview.AccessibleName="Предпросмотр кода";var buttons=new FlowLayoutPanel{Dock=DockStyle.Bottom,AutoSize=true};var generate=new Button{Text="Создать код",AutoSize=true};buttons.Controls.AddRange(new Control[]{generate,save,copy});Controls.Add(preview);Controls.Add(content);Controls.Add(format);Controls.Add(status);Controls.Add(buttons);generate.Click+=(s,e)=>Generate();save.Click+=(s,e)=>{if(preview.Image==null)return;using(var d=new SaveFileDialog{Filter="Изображение PNG|*.png",FileName="WinUp-code.png",OverwritePrompt=true})if(d.ShowDialog(this)==DialogResult.OK)try{preview.Image.Save(d.FileName,ImageFormat.Png);}catch(Exception ex){status.Text=ex.Message;}};copy.Click+=(s,e)=>{if(preview.Image!=null)try{Clipboard.SetImage(preview.Image);status.Text="Картинка скопирована. Она содержит введённые данные.";}catch(Exception ex){status.Text=ex.Message;}};content.TextChanged+=(s,e)=>ResetImage();format.SelectedIndexChanged+=(s,e)=>ResetImage();ResetImage();FormClosed+=(s,e)=>{ResetImage();content.Clear();};Appearance.Apply(this);preview.BackColor=Color.White;}
        void ResetImage(){var old=preview.Image;preview.Image=null;if(old!=null)old.Dispose();save.Enabled=copy.Enabled=false;status.Text="Создание выполняется на этом ПК. QR-код не шифрует введённые данные.";}
        void Generate(){ResetImage();try{preview.Image=CodeImages.Create(content.Text,new[]{"QR_CODE","CODE_128","EAN_13"}[format.SelectedIndex]);save.Enabled=copy.Enabled=true;status.Text="Код готов. Перед использованием проверьте его сканером.";}catch(Exception ex){status.Text=ex.Message;}}
    }
}
