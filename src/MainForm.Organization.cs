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
        readonly ComboBox passwordGroup=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,Width=190};
        readonly ComboBox passwordTag=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,Width=150};
        bool fillingPasswordFilters;
        FlowLayoutPanel BuildPasswordFilters(){
            var bar=Bar();bar.Controls.Add(new Label{Text="Поиск:",AutoSize=true,Margin=new Padding(6,8,3,3)});
            bar.Controls.Add(passwordSearch);bar.Controls.Add(passwordCategory);bar.Controls.Add(passwordKind);bar.Controls.Add(passwordPinned);bar.Controls.Add(passwordCount);
            bar.Controls.Add(passwordGroup);bar.Controls.Add(passwordTag);
            passwordGroup.Items.Add("Все группы");passwordGroup.SelectedIndex=0;passwordTag.Items.Add("Все метки");passwordTag.SelectedIndex=0;
            passwordCategory.Items.Add("Все категории");passwordCategory.SelectedIndex=0;
            passwordKind.Items.AddRange(new object[]{"Все типы","Сайты","Приложения","Приложение / сайт"});passwordKind.SelectedIndex=0;
            EventHandler refresh=(s,e)=>{if(!fillingPasswordFilters&&vault!=null)RefreshEntries();};
            passwordSearch.TextChanged+=refresh;passwordCategory.SelectedIndexChanged+=refresh;passwordKind.SelectedIndexChanged+=refresh;passwordPinned.CheckedChanged+=refresh;
            passwordGroup.SelectedIndexChanged+=refresh;passwordTag.SelectedIndexChanged+=refresh;
            Btn(bar,"Сбросить фильтры",(s,e)=>{fillingPasswordFilters=true;try{passwordSearch.Clear();passwordCategory.SelectedIndex=0;passwordKind.SelectedIndex=0;passwordGroup.SelectedIndex=0;passwordTag.SelectedIndex=0;passwordPinned.Checked=false;}finally{fillingPasswordFilters=false;}if(vault!=null)RefreshEntries();});
            return bar;
        }
        void RefreshPasswordCategories(){
            string selected=passwordCategory.SelectedItem as string;
            var available=AccountOrganization.Categories.Concat(vault.Entries.Select(e=>AccountOrganization.Category(e,store.Templates))).Distinct(StringComparer.CurrentCultureIgnoreCase).OrderBy(c=>c,StringComparer.CurrentCultureIgnoreCase).ToArray();
            fillingPasswordFilters=true;
            try{passwordCategory.Items.Clear();passwordCategory.Items.Add("Все категории");passwordCategory.Items.AddRange(available);passwordCategory.SelectedItem=selected??"Все категории";if(passwordCategory.SelectedIndex<0)passwordCategory.SelectedIndex=0;
                var group=passwordGroup.SelectedItem as AccountGroupInfo;passwordGroup.Items.Clear();passwordGroup.Items.Add("Все группы");foreach(var g in vault.AccountGroups())passwordGroup.Items.Add(g);passwordGroup.SelectedItem=passwordGroup.Items.OfType<AccountGroupInfo>().FirstOrDefault(g=>group!=null&&g.Id==group.Id);if(passwordGroup.SelectedIndex<0)passwordGroup.SelectedIndex=0;
                string tag=passwordTag.SelectedItem as string;passwordTag.Items.Clear();passwordTag.Items.Add("Все метки");passwordTag.Items.AddRange(vault.Entries.SelectMany(e=>e.Tags).Distinct(StringComparer.CurrentCultureIgnoreCase).OrderBy(t=>t,StringComparer.CurrentCultureIgnoreCase).ToArray());passwordTag.SelectedItem=tag;if(passwordTag.SelectedIndex<0)passwordTag.SelectedIndex=0;
            }
            finally{fillingPasswordFilters=false;}
        }
        void TogglePinnedPassword(){
            if(vault==null)return;var entry=SelectedEntry();if(entry==null)return;bool old=entry.Pinned;entry.Pinned=!old;
            if(!SaveVault())entry.Pinned=old;RefreshEntries();
        }
    }
}
