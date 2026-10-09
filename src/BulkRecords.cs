using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Forms;

namespace WinUp {
    sealed class BulkRecordDialog:Dlg,ILockableDialog {
        readonly CheckBox categoryChange=new CheckBox{Text="Изменить категорию",AutoSize=true},browserChange=new CheckBox{Text="Изменить браузер",AutoSize=true},delayChange=new CheckBox{Text="Изменить задержку запуска приложения",AutoSize=true};
        readonly TextBox category=new TextBox{Width=300,MaxLength=80};readonly ComboBox browser=new ComboBox{Width=300,DropDownStyle=ComboBoxStyle.DropDownList};readonly NumericUpDown delay=new NumericUpDown{Maximum=60,Width=100};
        readonly CheckBox pinned=new CheckBox{Text="Закрепление",ThreeState=true,CheckState=CheckState.Indeterminate,AutoSize=true},enter=new CheckBox{Text="Нажатие Enter после ввода",ThreeState=true,CheckState=CheckState.Indeterminate,AutoSize=true};
        internal BulkRecordDialog(int count):base("Изменить отмеченные записи"){
            Note("Записей: "+count+". Меняются только включённые параметры. Серый квадрат означает «оставить как есть». Для пустой категории включите изменение и оставьте поле пустым.");
            Row("",categoryChange);Row("Категория:",category);Row("",browserChange);Row("Браузер:",browser);Row("",delayChange);Row("Задержка, с:",delay);Row("",pinned);Row("",enter);Buttons();
            browser.Items.Add("Общий / системный");foreach(var item in Browsers.Installed())browser.Items.Add(item.Name);browser.SelectedIndex=0;category.Enabled=browser.Enabled=delay.Enabled=false;
            categoryChange.CheckedChanged+=(s,e)=>category.Enabled=categoryChange.Checked;browserChange.CheckedChanged+=(s,e)=>browser.Enabled=browserChange.Checked;delayChange.CheckedChanged+=(s,e)=>delay.Enabled=delayChange.Checked;
            Ok.Click+=(s,e)=>{if(!categoryChange.Checked&&!browserChange.Checked&&!delayChange.Checked&&pinned.CheckState==CheckState.Indeterminate&&enter.CheckState==CheckState.Indeterminate)Fail("Выберите хотя бы один параметр.");};
        }
        internal void Apply(LoginEntry record){if(categoryChange.Checked)record.Category=category.Text.Trim();if(browserChange.Checked&&record.Kind!="app")record.Browser=browser.SelectedIndex==0?"":(string)browser.SelectedItem;if(delayChange.Checked&&(record.Kind=="app"||record.Kind=="both"))record.Delay=(int)delay.Value;if(pinned.CheckState!=CheckState.Indeterminate)record.Pinned=pinned.Checked;if(enter.CheckState!=CheckState.Indeterminate)record.AutoEnter=enter.Checked;}
    }
    partial class MainForm {
        void BulkEditPasswords(){
            if(vault==null)return;var current=vault;var selected=pwList.CheckedItems.Cast<ListViewItem>().Select(i=>(LoginEntry)i.Tag).ToList();
            if(selected.Count==0){MessageBox.Show(this,"Отметьте галочками записи, которые нужно изменить.","WinUp");return;}
            using(var dialog=new BulkRecordDialog(selected.Count)){if(dialog.ShowDialog(this)!=DialogResult.OK||vault!=current)return;var copies=new List<LoginEntry>();bool kept=false;
                try{foreach(var record in selected){int index=current.Entries.IndexOf(record);if(index<0)throw new InvalidOperationException("Список изменился. Выберите записи заново.");var copy=record.Copy();copies.Add(copy);dialog.Apply(copy);current.Entries[index]=copy;}
                    if(SaveVault()){kept=true;foreach(var record in selected)record.ClearSecrets();PwLog("Изменено отмеченных записей: "+copies.Count+". Прежние версии сохранены в истории.");}
                }finally{if(!kept){for(int i=0;i<copies.Count;i++){int index=current.Entries.IndexOf(copies[i]);if(vault==current&&index>=0)current.Entries[index]=selected[i];copies[i].ClearSecrets();}if(vault!=current)foreach(var record in selected)record.ClearSecrets();}}
            }
        }
    }
}
