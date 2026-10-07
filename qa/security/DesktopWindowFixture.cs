using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

static class DesktopWindowFixture {
    [STAThread] static int Main(string[] args) {
        string root=Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory);
        if(!root.StartsWith(@"C:\WinUpAudit\",StringComparison.OrdinalIgnoreCase) || args.Length!=2) return 99;
        string proof=Path.GetFullPath(args[1]);
        if(!proof.StartsWith(root,StringComparison.OrdinalIgnoreCase)) return 98;
        Application.EnableVisualStyles();
        using(var window=new Form {Text=args[0],Width=420,Height=150,ShowInTaskbar=true})
        using(var timer=new Timer {Interval=60000}) {
            window.Controls.Add(new Label {Text="Synthetic window ownership probe. No input or secrets.",Dock=DockStyle.Fill});
            window.Shown+=delegate {
                string temporary=proof+".part";
                File.WriteAllText(temporary,window.Handle.ToInt64()+"|"+Process.GetCurrentProcess().Id);
                File.Move(temporary,proof);timer.Start();
            };
            timer.Tick+=delegate {window.Close();};
            Application.Run(window);
        }
        return 0;
    }
}
