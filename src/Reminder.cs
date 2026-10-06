using System;
using System.Globalization;
using Microsoft.Win32;

namespace WinUp
{
    // Напоминание «давно не проверяли обновления» (крипто-ядро и программы winget).
    // Само в интернет не ходит — только предлагает. Дата хранится в HKCU, а не в apps.json:
    // доверие к обновлённому ядру привязано к компьютеру, и после переноса на новый ПК
    // напоминание сразу подскажет, что здесь обновления ещё не проверялись.
    public static class Reminder
    {
        public const int PeriodDays = 90;
        const string Key = @"Software\WinUp\UpdateCheck";
        const string Fmt = "yyyy-MM-dd";

        static DateTime? ReadDate(string name)
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(Key))
                {
                    var v = k == null ? null : k.GetValue(name) as string;
                    DateTime d;
                    if (v != null && DateTime.TryParseExact(v, Fmt, CultureInfo.InvariantCulture, DateTimeStyles.None, out d)) return d;
                }
            }
            catch { }
            return null;
        }

        static void Write(string name, object value)
        {
            try { using (var k = Registry.CurrentUser.CreateSubKey(Key)) k.SetValue(name, value); }
            catch { }
        }

        public static DateTime? LastCheck { get { return ReadDate("LastCheck"); } }

        public static bool Enabled
        {
            get
            {
                try { using (var k = Registry.CurrentUser.OpenSubKey(Key)) return k == null || !(k.GetValue("Off") is int) || (int)k.GetValue("Off") == 0; }
                catch { return true; }
            }
            set { Write("Off", value ? 0 : 1); }
        }

        // Проверка выполнена (ядро или программы): следующее напоминание — через PeriodDays.
        public static void MarkChecked()
        {
            Write("LastCheck", DateTime.Today.ToString(Fmt, CultureInfo.InvariantCulture));
            Write("SnoozeUntil", "");
        }

        public static void Snooze(int days)
        {
            Write("SnoozeUntil", DateTime.Today.AddDays(days).ToString(Fmt, CultureInfo.InvariantCulture));
        }

        // Самый первый запуск свежей копии: ядро в ней новое, напоминать с порога незачем — отсчёт с сегодняшнего дня.
        public static void StartCountdownIfNew()
        {
            if (LastCheck == null) MarkChecked();
        }

        // null — напоминать не нужно; иначе текст плашки.
        public static string Due(DateTime today)
        {
            if (!Enabled) return null;
            var snooze = ReadDate("SnoozeUntil");
            if (snooze != null && today < snooze.Value) return null;
            var last = LastCheck;
            if (last == null) return "Обновления на этом ПК ещё не проверялись.";
            int days = (int)(today - last.Value).TotalDays;
            if (days < PeriodDays) return null;
            return "Обновления не проверялись с " + last.Value.ToString("dd.MM.yyyy") + " (" + days + " дн.).";
        }
    }
}
