using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace WinUp {
    partial class MainForm {
        readonly ListView cardList=new ListView{Dock=DockStyle.Fill,View=View.Details,FullRowSelect=true,HideSelection=false};
        readonly List<Button> cardButtons=new List<Button>();
        void CardButtonsState(){foreach(var button in cardButtons){string action=(string)button.Tag;button.Enabled=action=="Открыть базу"?vault==null:vault!=null&&(action=="Добавить карту"||cardList.SelectedItems.Count==1);}}
        void BuildCardsTab(){
            var page=new TabPage("Карты");var bar=new FlowLayoutPanel{Dock=DockStyle.Top,AutoSize=true};
            foreach(var action in new[]{"Добавить карту","Изменить карту","Копировать номер","Удалить карту","Открыть базу"}){var button=new Button{Text=action,Tag=action,AutoSize=true};cardButtons.Add(button);string name=action;button.Click+=(s,e)=>{try{if(name=="Открыть базу"){Unlock();return;}var card=cardList.SelectedItems.Count==1?cardList.SelectedItems[0].Tag as BankCard:null;CardAction(name=="Добавить карту"?"add":name=="Изменить карту"?"edit":name=="Удалить карту"?"delete":"copy",card==null?null:card.Id,"number");}catch(Exception ex){MessageBox.Show(this,ex.Message,"WinUp — карты");}};bar.Controls.Add(button);}
            cardList.SelectedIndexChanged+=(s,e)=>CardButtonsState();cardList.Columns.Add("Карта",220);cardList.Columns.Add("Номер",150);cardList.Columns.Add("Срок",100);cardList.DoubleClick+=(s,e)=>{try{if(cardList.SelectedItems.Count==1)CardAction("edit",((BankCard)cardList.SelectedItems[0].Tag).Id,"");}catch(Exception ex){MessageBox.Show(this,ex.Message,"WinUp — карты");}};page.Controls.Add(cardList);page.Controls.Add(bar);tabs.TabPages.Add(page);
        }
        void RefreshCards(){string selected=cardList.SelectedItems.Count==1?((BankCard)cardList.SelectedItems[0].Tag).Id:null;cardList.Items.Clear();if(vault!=null)foreach(var card in vault.Cards){var row=new ListViewItem(card.Name){Tag=card};row.SubItems.Add(card.Brand+" •••• "+card.LastFour);row.SubItems.Add(card.Expiry+(card.NeedsReview?" · проверьте данные":card.Expired?" · истекла":""));cardList.Items.Add(row);if(card.Id==selected)row.Selected=true;}if(cardList.SelectedItems.Count==0&&cardList.Items.Count>0)cardList.Items[0].Selected=true;CardButtonsState();}
        void CardAction(string action,string id,string field){
            var active=vault;if(active==null)throw new IOException("Сначала откройте базу.");var card=action=="add"?null:active.Cards.FirstOrDefault(c=>c.Id==id);
            if(action=="add"||action=="edit"){
                if(action=="edit"&&card==null)throw new IOException("Выберите карту.");
                using(var dialog=new BankCardDialog(card,candidate=>active.Cards.Any(c=>c!=card&&c.UseNumber(n=>candidate.UseNumber(other=>n==other))))){if(dialog.ShowDialog(this)!=DialogResult.OK)return;if(vault!=active){dialog.Result.Clear();throw new IOException("База заблокирована.");}var changed=dialog.Result;int index=card==null?-1:active.Cards.IndexOf(card);if(index<0)active.Cards.Add(changed);else active.Cards[index]=changed;
                    if(!SaveVaultOf(active)){changed.Clear();LockVault();return;}if(card!=null)card.Clear();}
            }else {
                if(card==null)throw new IOException("Выберите карту.");
                if(action=="delete"){if(MessageBox.Show(this,"Переместить карту «"+card.Name+"» в корзину?","WinUp — карты",MessageBoxButtons.YesNo)!=DialogResult.Yes)return;if(vault!=active)return;active.Cards.Remove(card);if(!SaveVaultOf(active)){card.Clear();LockVault();return;}card.Clear();}
                else if(action=="copy"){if(field=="number")card.UseNumber(n=>{SecureClip.Copy(n);return 0;});else if(field=="cvv")card.UseCvv(c=>{SecureClip.Copy(c??"");return 0;});else if(field=="expiry")SecureClip.Copy(card.Expiry);else if(field=="holder")SecureClip.Copy(card.Holder??"");else throw new IOException("Неизвестное поле карты.");}
                else throw new IOException("Неизвестное действие.");
            }RefreshCards();
        }
    }
    sealed class BankCardDialog:Dlg,ILockableDialog {
        readonly TextBox name=new TextBox(),holder=new TextBox(),number=new TextBox{UseSystemPasswordChar=true},cvv=new TextBox{UseSystemPasswordChar=true,MaxLength=4},notes=new TextBox{Multiline=true,Height=90,ScrollBars=ScrollBars.Vertical};
        readonly NumericUpDown month=new NumericUpDown{Minimum=1,Maximum=12},year=new NumericUpDown{Minimum=2000,Maximum=2199};readonly string id;readonly Label feedback;
        internal BankCard Result;
        internal BankCardDialog(BankCard card,Func<BankCard,bool> duplicate=null):base(card==null?"Добавить банковскую карту":"Изменить банковскую карту"){
            id=card==null?null:card.Id;Row("Название:",name);Row("Номер карты:",number);Row("Держатель:",holder);var expiry=new FlowLayoutPanel{AutoSize=true};expiry.Controls.AddRange(new Control[]{month,new Label{Text="/",AutoSize=true},year});Row("Действует до:",expiry);Row("CVV/CVC:",cvv);Row("Заметка:",notes);
            var show=new CheckBox{Text="Показать номер и CVV/CVC",AutoSize=true};show.CheckedChanged+=(s,e)=>{number.UseSystemPasswordChar=cvv.UseSystemPasswordChar=!show.Checked;};FullRow(show);
            Note("Данные сохраняются в зашифрованной базе. Вводить PIN-код карты здесь не нужно.");
            month.Value=card==null||card.Month<1||card.Month>12?DateTime.Today.Month:card.Month;year.Value=card==null||card.Year<2000||card.Year>2199?DateTime.Today.Year+3:card.Year;
            if(card!=null&&card.NeedsReview)Note("Проверьте данные этой карты перед сохранением: запись содержит неверное или незаполненное поле.");
            if(card!=null){name.Text=card.Name;holder.Text=card.Holder;card.UseNumber(n=>{var handle=number.Handle;number.Text=n;return 0;});card.UseCvv(c=>{var handle=cvv.Handle;cvv.Text=c;return 0;});card.UseNotes(n=>{var handle=notes.Handle;notes.Text=n;return 0;});}
            feedback=Note("");feedback.AccessibleName="Ошибка сохранения карты";
            Buttons();Ok.Click+=(s,e)=>{BankCard candidate=null;try{candidate=new BankCard{Id=id,Name=name.Text.Trim(),Holder=holder.Text.Trim(),Month=(int)month.Value,Year=(int)year.Value};candidate.Number=BankCard.NormalizeNumber(number.Text);candidate.Cvv=cvv.Text.Trim();candidate.Notes=notes.Text;candidate.Validate();if(duplicate!=null&&duplicate(candidate))throw new IOException("Карта с таким номером уже сохранена. Измените существующую запись.");Result=candidate;}catch(Exception ex){if(candidate!=null)candidate.Clear();DialogResult=DialogResult.None;feedback.Text=ex.Message;}};
        }
    }
}
