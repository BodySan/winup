using System;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Windows.Forms;
namespace WinUp {
    static class QrDensityProbe {
        static int checks;static Assembly readerLibrary;
        static void Check(string name,bool ok){if(!ok)throw new Exception(name);Console.WriteLine("PASS "+name);checks++;}
        static object Decode(Bitmap image){var reader=Activator.CreateInstance(readerLibrary.GetType("ZXing.BarcodeReader"));return reader.GetType().GetMethod("Decode",new[]{typeof(Bitmap)}).Invoke(reader,new object[]{image});}
        [STAThread]static int Main(string[] args){
            if(!Path.GetFileName(Paths.Root).StartsWith("notes-qa-"))return 2;
            bool ui=args.Contains("--file-report");if(ui)Console.SetOut(new StreamWriter(Path.Combine(Paths.Root,"feature-results.txt")){AutoFlush=true});
            try{readerLibrary=Assembly.Load(File.ReadAllBytes(Path.Combine(Paths.Root,"zxing.dll")));int first=0,last=0;
                foreach(int version in new[]{1,10,40})using(var image=CodeImages.Create("WINUP-42","QR_CODE",version,"M")){var result=Decode(image);Check("QR fixed version "+version+" roundtrip",result!=null&&(string)result.GetType().GetProperty("Text").GetValue(result,null)=="WINUP-42");int bytes=((byte[])result.GetType().GetProperty("RawBytes").GetValue(result,null)).Length;if(version==1)first=bytes;if(version==40)last=bytes;}
                Check("Version 40 has denser matrix than version 1",last>first);
                foreach(string level in new[]{"L","M","Q","H"})using(var image=CodeImages.Create("WINUP","QR_CODE",5,level)){var result=Decode(image);var metadata=(System.Collections.IDictionary)result.GetType().GetProperty("ResultMetadata").GetValue(result,null);Check("Error correction "+level,Convert.ToString(metadata[Enum.Parse(readerLibrary.GetType("ZXing.ResultMetadataType"),"ERROR_CORRECTION_LEVEL")])==level);}
                bool rejected=false;try{using(var unused=CodeImages.Create(new string('x',500),"QR_CODE",1)){}}catch(IOException ex){rejected=ex.Message.Contains("Авто");}Check("Too-small matrix gives actionable error",rejected);
                using(var image=CodeImages.Create(new string('x',500),"QR_CODE")){var result=Decode(image);Check("Auto fits longer content",result!=null&&((string)result.GetType().GetProperty("Text").GetValue(result,null)).Length==500);}
                foreach(int version in new[]{-1,41}){rejected=false;try{using(var unused=CodeImages.Create("WinUp","QR_CODE",version)){}}catch(IOException){rejected=true;}Check("Invalid QR version "+version+" rejected",rejected);}
                if(ui)CheckUi();Console.WriteLine("RESULT passed="+checks+" failed=0");return 0;
            }catch(Exception ex){Console.WriteLine("FAIL "+ex);return 1;}
        }
        static T Field<T>(object obj,string name){return (T)obj.GetType().GetField(name,BindingFlags.NonPublic|BindingFlags.Instance).GetValue(obj);}
        static void Generate(CodeImageDialog dialog){typeof(CodeImageDialog).GetMethod("Generate",BindingFlags.NonPublic|BindingFlags.Instance).Invoke(dialog,null);}
        static void CheckUi(){Application.EnableVisualStyles();using(var dialog=new CodeImageDialog()){
            dialog.Show();Application.DoEvents();var density=Field<ComboBox>(dialog,"density");var level=Field<ComboBox>(dialog,"correction");var format=Field<ComboBox>(dialog,"format");var text=Field<TextBox>(dialog,"content");var image=Field<PictureBox>(dialog,"preview");
            Check("Auto and all 40 versions available",density.Items.Count==41&&density.SelectedIndex==0);text.Text="WINUP-42";density.SelectedIndex=40;Generate(dialog);Check("Dense QR preview available",image.Image!=null);
            density.SelectedIndex=1;Check("Density change clears stale preview",image.Image==null&&!Field<Button>(dialog,"save").Enabled);Generate(dialog);level.SelectedIndex=3;Check("Correction change clears stale preview",image.Image==null);Generate(dialog);Check("High correction QR can be created",image.Image!=null);
            text.Text=new string('x',500);Generate(dialog);Check("Capacity failure disables export",image.Image==null&&!Field<Button>(dialog,"save").Enabled&&!Field<Button>(dialog,"copy").Enabled);
            format.SelectedIndex=1;text.Text="WINUP-42";Generate(dialog);Check("Barcode ignores QR controls",!density.Enabled&&!level.Enabled&&image.Image!=null);format.SelectedIndex=0;level.SelectedIndex=1;density.SelectedIndex=20;Generate(dialog);Check("QR controls restored",density.Enabled&&level.Enabled&&image.Image!=null);
            using(var bitmap=new Bitmap(dialog.Width,dialog.Height)){dialog.DrawToBitmap(bitmap,new Rectangle(Point.Empty,bitmap.Size));bitmap.Save(Path.Combine(Paths.Root,"qr-density-window.png"));}
            dialog.Size=dialog.MinimumSize;Application.DoEvents();var bounds=dialog.RectangleToScreen(dialog.ClientRectangle);Check("Density selector fits minimum window",bounds.Contains(density.RectangleToScreen(density.ClientRectangle))&&bounds.Contains(level.RectangleToScreen(level.ClientRectangle))&&image.Height>=100);
        }}
    }
}
