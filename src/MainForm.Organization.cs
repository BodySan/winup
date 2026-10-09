using System;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace WinUp {
    partial class MainForm {
        readonly TextBox passwordSearch=new TextBox{Width=200};
        readonly ComboBox passwordCategory=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,Width=170};
        readonly ComboBox passwordKind=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,Width=150};
        readonly CheckBox passwordPinned=new CheckBox{Text="Только закреплённые",AutoSize=true};
        readonly Label passwordCount=new Label{AutoSize=true,Margin=new Padding(6,8,3,3)};
        bool fillingPasswordFilters;
        FlowLayoutPanel BuildPasswordFilters(){
            var bar=Bar();bar.Controls.Add(new Label{Text="Поиск:",AutoSize=true,Margin=new Padding(6,8,3,3)});
            bar.Controls.Add(passwordSearch);bar.Controls.Add(passwordCategory);bar.Controls.Add(passwordKind);bar.Controls.Add(passwordPinned);bar.Controls.Add(passwordCount);
            passwordCategory.Items.Add("Все категории");passwordCategory.SelectedIndex=0;
            passwordKind.Items.AddRange(new object[]{"Все типы","Сайты","Приложения","Приложение / сайт"});passwordKind.SelectedIndex=0;
            EventHandler refresh=(s,e)=>{if(!fillingPasswordFilters&&vault!=null)RefreshEntries();};
            passwordSearch.TextChanged+=refresh;passwordCategory.SelectedIndexChanged+=refresh;passwordKind.SelectedIndexChanged+=refresh;passwordPinned.CheckedChanged+=refresh;
            Btn(bar,"Сбросить фильтры",(s,e)=>{fillingPasswordFilters=true;try{passwordSearch.Clear();passwordCategory.SelectedIndex=0;passwordKind.SelectedIndex=0;passwordPinned.Checked=false;}finally{fillingPasswordFilters=false;}if(vault!=null)RefreshEntries();});
            return bar;
        }
        void RefreshPasswordCategories(){
            string selected=passwordCategory.SelectedItem as string;
            var available=AccountOrganization.Categories.Concat(vault.Entries.Select(e=>AccountOrganization.Category(e,store.Templates))).Distinct(StringComparer.CurrentCultureIgnoreCase).OrderBy(c=>c,StringComparer.CurrentCultureIgnoreCase).ToArray();
            fillingPasswordFilters=true;
            try{passwordCategory.Items.Clear();passwordCategory.Items.Add("Все категории");passwordCategory.Items.AddRange(available);passwordCategory.SelectedItem=selected??"Все категории";if(passwordCategory.SelectedIndex<0)passwordCategory.SelectedIndex=0;}
            finally{fillingPasswordFilters=false;}
        }
        void TogglePinnedPassword(){
            if(vault==null)return;var entry=SelectedEntry();if(entry==null)return;bool old=entry.Pinned;entry.Pinned=!old;
            if(!SaveVault())entry.Pinned=old;RefreshEntries();
        }
    }
}
